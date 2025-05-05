"""
Combined Malware Detection System
Menggabungkan kelebihan dari kedua implementasi dengan insights dari analisis
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report, silhouette_score, calinski_harabasz_score, davies_bouldin_score
from sklearn.decomposition import PCA

class CombinedMalwareDetector:
    def __init__(self, n_clusters=5, random_state=42):
        self.n_clusters = n_clusters
        self.random_state = random_state
        self.scaler = RobustScaler()
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=random_state, n_init=10)
        self.suspicious_clusters = []
        self.cluster_stats = {}
        
        # Critical thresholds based on analysis
        self.thresholds = {
            'entropy_high': 315,        # ProcessImageEntropy for malware
            'entropy_suspicious': 300,   # ProcessImageEntropy for suspicious
            'sensitive_keys_high': 5000, # SensitiveKeysAccessed for malware
            'sensitive_keys_suspicious': 1000,
            'registry_entropy_high': 300,
            'ops_per_second': 1000,     # TotalOperationCount/ProcessAgeSeconds
            'query_per_second': 1000,
            'process_age_short': 30,    # seconds
            'process_hijack_normal': {
                'services.exe': 20,
                'svchost.exe': 3.25,
                'default': 5
            },
            'com_object_normal': {
                'svchost.exe': 2.12,
                'default': 0.5
            }
        }
        
    def prepare_features(self, data):
        """Prepare features including time-normalized ones"""
        # Add time-normalized features
        data['OpsPerSecond'] = data['TotalOperationCount'] / (data['ProcessAgeSeconds'] + 1)
        data['QueryPerSecond'] = data['QueryOperationCount'] / (data['ProcessAgeSeconds'] + 1)
        data['UniqueKeysPerSecond'] = data['UniqueKeysAccessed'] / (data['ProcessAgeSeconds'] + 1)
        data['EntropyImageValueRatio'] = data['ProcessImageEntropy'] / (data['RegistryValueEntropyAvg'] + 1)
        
        # Features for clustering (based on your analysis)
        features = [
            'ProcessImageEntropy',      # Always highest for malware
            'SensitiveKeysAccessed',    # Fixed highest anomaly  
            'ProcessHijackKeysAccessed', # Non-zero for malware
            'ComObjectKeysAccessed',     # Non-zero for malware
            'RegistryValueEntropyAvg',   # Sometimes highest
            'QueryOperationCount',       # Important per your finding
            'UniqueKeysAccessed',        # Important per your finding
            'OpsPerSecond',             # Time-normalized
            'QueryPerSecond',           # Time-normalized
            'ProcessAgeSeconds'         # For context
        ]
        
        return data, features
    
    def fit(self, data, features):
        """Fit K-Means model and identify suspicious clusters"""
        X = data[features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        
        self.cluster_labels = self.kmeans.fit_predict(X_scaled)
        data['Cluster'] = self.cluster_labels
        
        # Calculate cluster statistics
        self._calculate_cluster_stats(data)
        self._identify_suspicious_clusters(data)
        
        return self.cluster_labels
    
    def _calculate_cluster_stats(self, data):
        """Calculate detailed statistics for each cluster"""
        for i in range(self.n_clusters):
            cluster_data = data[data['Cluster'] == i]
            self.cluster_stats[i] = {
                'size': len(cluster_data),
                'avg_process_image_entropy': cluster_data['ProcessImageEntropy'].mean(),
                'avg_sensitive_keys': cluster_data['SensitiveKeysAccessed'].mean(),
                'avg_registry_entropy': cluster_data['RegistryValueEntropyAvg'].mean(),
                'avg_ops_per_second': cluster_data['OpsPerSecond'].mean(),
                'avg_query_per_second': cluster_data['QueryPerSecond'].mean(),
                'avg_process_age': cluster_data['ProcessAgeSeconds'].mean(),
                'max_process_image_entropy': cluster_data['ProcessImageEntropy'].max(),
                'max_sensitive_keys': cluster_data['SensitiveKeysAccessed'].max()
            }
    
    def _identify_suspicious_clusters(self, data):
        """Identify clusters likely to contain malware"""
        self.suspicious_clusters = []
        
        for i, stats in self.cluster_stats.items():
            if (stats['avg_process_image_entropy'] > self.thresholds['entropy_suspicious'] or
                stats['avg_sensitive_keys'] > self.thresholds['sensitive_keys_suspicious'] or
                stats['max_process_image_entropy'] > self.thresholds['entropy_high'] or
                stats['avg_registry_entropy'] > self.thresholds['registry_entropy_high'] or
                (stats['avg_ops_per_second'] > self.thresholds['ops_per_second'] and 
                 stats['avg_process_age'] < self.thresholds['process_age_short'])):
                self.suspicious_clusters.append(i)
    
    def classify_process(self, row):
        """Classify a single process using hybrid approach"""
        process_name = row['ProcessName'].lower() if pd.notna(row['ProcessName']) else ''
        
        # Rule 1: Strong malware indicators (highest priority)
        if (row['ProcessImageEntropy'] > self.thresholds['entropy_high'] and 
            row['SensitiveKeysAccessed'] > self.thresholds['sensitive_keys_high']):
            return 'malware', 'Rule1: High entropy + sensitive keys'
        
        # Rule 2: Extreme sensitive keys access
        if row['SensitiveKeysAccessed'] > self.thresholds['sensitive_keys_high'] * 2:
            return 'malware', 'Rule2: Extreme sensitive keys access'
        
        # Rule 3: Time-based anomaly detection
        if (row['OpsPerSecond'] > self.thresholds['ops_per_second'] and 
            row['ProcessAgeSeconds'] < self.thresholds['process_age_short']):
            return 'suspicious', 'Rule3: High operation rate in short time'
        
        # Rule 4: High entropy with high registry value entropy
        if (row['ProcessImageEntropy'] > self.thresholds['entropy_high'] and 
            row['RegistryValueEntropyAvg'] > self.thresholds['registry_entropy_high']):
            return 'malware', 'Rule4: High process + registry entropy'
        
        # Rule 5: Check for known process anomalies
        if self._check_process_anomaly(row, process_name):
            return 'suspicious', 'Rule5: Process-specific anomaly'
        
        # Rule 6: Cluster-based detection
        if 'Cluster' in row and row['Cluster'] in self.suspicious_clusters:
            if row['ProcessImageEntropy'] > self.thresholds['entropy_suspicious']:
                return 'suspicious', 'Rule6: Suspicious cluster + high entropy'
            elif row['SensitiveKeysAccessed'] > self.thresholds['sensitive_keys_suspicious']:
                return 'suspicious', 'Rule7: Suspicious cluster + sensitive keys'
        
        # Rule 7: Moderate indicators
        if (row['ProcessImageEntropy'] > self.thresholds['entropy_suspicious'] or 
            row['SensitiveKeysAccessed'] > self.thresholds['sensitive_keys_suspicious']):
            return 'suspicious', 'Rule8: Moderate suspicious indicators'
        
        return 'benign', 'No malicious indicators detected'
    
    def _check_process_anomaly(self, row, process_name):
        """Check for process-specific anomalies"""
        # Check ProcessHijackKeysAccessed
        if 'services.exe' in process_name:
            if row['ProcessHijackKeysAccessed'] > self.thresholds['process_hijack_normal']['services.exe'] * 1.5:
                return True
        elif 'svchost.exe' in process_name:
            if row['ProcessHijackKeysAccessed'] > self.thresholds['process_hijack_normal']['svchost.exe'] * 1.5:
                return True
            if row['ComObjectKeysAccessed'] > self.thresholds['com_object_normal']['svchost.exe'] * 1.5:
                return True
        else:
            if row['ProcessHijackKeysAccessed'] > self.thresholds['process_hijack_normal']['default']:
                return True
        
        return False
    
    def predict(self, data, features):
        """Predict classifications for all processes"""
        X = data[features].fillna(0)
        X_scaled = self.scaler.transform(X)
        cluster_labels = self.kmeans.predict(X_scaled)
        
        classifications = []
        reasons = []
        
        for idx, row in data.iterrows():
            row_with_cluster = row.copy()
            row_with_cluster['Cluster'] = cluster_labels[idx]
            classification, reason = self.classify_process(row_with_cluster)
            classifications.append(classification)
            reasons.append(reason)
        
        return classifications, reasons
    
    def visualize_results(self, data, features, classifications):
        """Create comprehensive visualization of results"""
        fig = plt.figure(figsize=(20, 15))
        
        # 1. PCA visualization
        ax1 = plt.subplot(2, 3, 1)
        X = data[features].fillna(0)
        X_scaled = self.scaler.transform(X)
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        colors = {'benign': 'green', 'suspicious': 'orange', 'malware': 'red'}
        for class_type in colors:
            mask = np.array(classifications) == class_type
            ax1.scatter(X_pca[mask, 0], X_pca[mask, 1], 
                       c=colors[class_type], label=class_type, alpha=0.6)
        
        ax1.set_title('PCA Visualization of Classifications')
        ax1.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        ax1.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        ax1.legend()
        
        # 2. Key features scatter
        ax2 = plt.subplot(2, 3, 2)
        scatter = ax2.scatter(data['ProcessImageEntropy'], 
                             data['SensitiveKeysAccessed'], 
                             c=[colors[c] for c in classifications], 
                             alpha=0.6)
        ax2.set_xlabel('Process Image Entropy')
        ax2.set_ylabel('Sensitive Keys Accessed')
        ax2.set_yscale('log')
        ax2.set_title('Primary Detection Features')
        ax2.axvline(x=self.thresholds['entropy_high'], color='red', linestyle='--', alpha=0.5)
        ax2.axhline(y=self.thresholds['sensitive_keys_high'], color='red', linestyle='--', alpha=0.5)
        
        # 3. Time-based analysis
        ax3 = plt.subplot(2, 3, 3)
        scatter = ax3.scatter(data['ProcessAgeSeconds'], 
                             data['OpsPerSecond'], 
                             c=[colors[c] for c in classifications], 
                             alpha=0.6)
        ax3.set_xlabel('Process Age (seconds)')
        ax3.set_ylabel('Operations per Second')
        ax3.set_yscale('log')
        ax3.set_title('Time-based Anomaly Detection')
        ax3.axvline(x=self.thresholds['process_age_short'], color='red', linestyle='--', alpha=0.5)
        ax3.axhline(y=self.thresholds['ops_per_second'], color='red', linestyle='--', alpha=0.5)
        
        # 4. Cluster characteristics
        ax4 = plt.subplot(2, 3, 4)
        cluster_df = pd.DataFrame(self.cluster_stats).T
        features_to_plot = ['avg_process_image_entropy', 'avg_sensitive_keys', 'avg_ops_per_second']
        cluster_df[features_to_plot].plot(kind='bar', ax=ax4)
        ax4.set_title('Cluster Characteristics')
        ax4.set_xlabel('Cluster')
        ax4.set_ylabel('Average Value')
        ax4.legend(loc='upper right')
        
        # 5. Classification distribution
        ax5 = plt.subplot(2, 3, 5)
        class_counts = pd.Series(classifications).value_counts()
        class_counts.plot(kind='pie', autopct='%1.1f%%', ax=ax5, colors=[colors[c] for c in class_counts.index])
        ax5.set_title('Classification Distribution')
        
        # 6. Detection summary
        ax6 = plt.subplot(2, 3, 6)
        summary_data = {
            'Total Processes': len(data),
            'Malware': sum(1 for c in classifications if c == 'malware'),
            'Suspicious': sum(1 for c in classifications if c == 'suspicious'),
            'Benign': sum(1 for c in classifications if c == 'benign'),
            'Detection Rate': f"{sum(1 for c in classifications if c != 'benign') / len(data) * 100:.1f}%"
        }
        
        # Create text summary
        ax6.axis('off')
        summary_text = "Detection Summary\n" + "="*20 + "\n\n"
        for key, value in summary_data.items():
            summary_text += f"{key}: {value}\n"
        
        # Add AvosLocker specific detection if present
        avoslocker_data = data[data['ProcessName'].str.contains('avoslocker', case=False, na=False)]
        if len(avoslocker_data) > 0:
            avos_classifications = [classifications[i] for i in avoslocker_data.index]
            detected = sum(1 for c in avos_classifications if c == 'malware')
            summary_text += f"\nAvosLocker Detection: {detected}/{len(avoslocker_data)} ({detected/len(avoslocker_data)*100:.1f}%)"
        
        ax6.text(0.1, 0.5, summary_text, transform=ax6.transAxes, fontsize=12, 
                verticalalignment='center', fontfamily='monospace')
        
        plt.tight_layout()
        plt.savefig('combined_malware_detection_results.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Additional detailed visualization
        self._create_detailed_analysis(data, classifications)
    
    def _create_detailed_analysis(self, data, classifications):
        """Create additional detailed analysis plots"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. Feature importance based on PCA
        features_for_pca = ['ProcessImageEntropy', 'SensitiveKeysAccessed', 'RegistryValueEntropyAvg',
                           'QueryOperationCount', 'UniqueKeysAccessed', 'OpsPerSecond']
        X = data[features_for_pca].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        pca = PCA()
        pca.fit(X_scaled)
        
        feature_importance = abs(pca.components_[0])
        importance_df = pd.DataFrame({'feature': features_for_pca, 'importance': feature_importance})
        importance_df = importance_df.sort_values('importance', ascending=True)
        
        importance_df.plot(kind='barh', x='feature', y='importance', ax=axes[0, 0], legend=False)
        axes[0, 0].set_title('Feature Importance (PCA)')
        axes[0, 0].set_xlabel('Importance')
        
        # 2. Process type distribution
        process_types = []
        for name in data['ProcessName']:
            if pd.isna(name):
                process_types.append('Unknown')
            elif 'avoslocker' in str(name).lower():
                process_types.append('AvosLocker')
            elif 'svchost.exe' in str(name).lower():
                process_types.append('svchost.exe')
            elif 'services.exe' in str(name).lower():
                process_types.append('services.exe')
            elif 'explorer.exe' in str(name).lower():
                process_types.append('explorer.exe')
            else:
                process_types.append('Other')
        
        process_class_df = pd.DataFrame({'ProcessType': process_types, 'Classification': classifications})
        process_pivot = pd.crosstab(process_class_df['ProcessType'], process_class_df['Classification'])
        process_pivot.plot(kind='bar', stacked=True, ax=axes[0, 1])
        axes[0, 1].set_title('Classifications by Process Type')
        axes[0, 1].set_xlabel('Process Type')
        axes[0, 1].set_ylabel('Count')
        axes[0, 1].legend(title='Classification')
        
        # 3. Suspicious cluster analysis
        suspicious_data = data[data['Cluster'].isin(self.suspicious_clusters)]
        axes[1, 0].scatter(suspicious_data['ProcessImageEntropy'], 
                          suspicious_data['SensitiveKeysAccessed'],
                          c=suspicious_data['Cluster'], cmap='viridis', alpha=0.6)
        axes[1, 0].set_xlabel('Process Image Entropy')
        axes[1, 0].set_ylabel('Sensitive Keys Accessed')
        axes[1, 0].set_yscale('log')
        axes[1, 0].set_title('Suspicious Clusters Analysis')
        
        # 4. Time-based patterns
        axes[1, 1].scatter(data['ProcessAgeSeconds'], data['QueryPerSecond'],
                          c=[{'benign': 'green', 'suspicious': 'orange', 'malware': 'red'}[c] 
                             for c in classifications], alpha=0.6)
        axes[1, 1].set_xlabel('Process Age (seconds)')
        axes[1, 1].set_ylabel('Queries per Second')
        axes[1, 1].set_yscale('log')
        axes[1, 1].set_title('Query Rate vs Process Age')
        
        plt.tight_layout()
        plt.savefig('detailed_malware_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
class OptimalClustersAnalyzer:
    def __init__(self, max_clusters=10):
        self.max_clusters = max_clusters
        self.scaler = RobustScaler()
        
    def find_optimal_clusters(self, data, features, method='all'):
        """
        Find optimal number of clusters using multiple methods
        
        Args:
            data: DataFrame with features
            features: List of feature columns
            method: 'elbow', 'silhouette', 'calinski', 'davies', or 'all'
        
        Returns:
            Dictionary with results from each method
        """
        X = data[features].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        
        results = {}
        k_range = range(2, self.max_clusters + 1)
        
        # Elbow Method
        if method in ['elbow', 'all']:
            inertias = []
            for k in k_range:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                kmeans.fit(X_scaled)
                inertias.append(kmeans.inertia_)
            results['elbow'] = {'k_values': list(k_range), 'scores': inertias}
        
        # Silhouette Method
        if method in ['silhouette', 'all']:
            silhouette_scores = []
            for k in k_range:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                labels = kmeans.fit_predict(X_scaled)
                score = silhouette_score(X_scaled, labels)
                silhouette_scores.append(score)
            results['silhouette'] = {'k_values': list(k_range), 'scores': silhouette_scores}
        
        # Calinski-Harabasz Method
        if method in ['calinski', 'all']:
            calinski_scores = []
            for k in k_range:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                labels = kmeans.fit_predict(X_scaled)
                score = calinski_harabasz_score(X_scaled, labels)
                calinski_scores.append(score)
            results['calinski'] = {'k_values': list(k_range), 'scores': calinski_scores}
        
        # Davies-Bouldin Method (lower is better)
        if method in ['davies', 'all']:
            davies_scores = []
            for k in k_range:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                labels = kmeans.fit_predict(X_scaled)
                score = davies_bouldin_score(X_scaled, labels)
                davies_scores.append(score)
            results['davies'] = {'k_values': list(k_range), 'scores': davies_scores}
        
        return results
    
    def plot_results(self, results):
        """Plot results from all methods"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Optimal Number of Clusters Analysis', fontsize=16)
        
        # Elbow Method
        if 'elbow' in results:
            ax = axes[0, 0]
            elbow_data = results['elbow']
            ax.plot(elbow_data['k_values'], elbow_data['scores'], 'bo-')
            ax.set_xlabel('Number of Clusters (k)')
            ax.set_ylabel('Inertia')
            ax.set_title('Elbow Method')
            ax.grid(True, alpha=0.3)
            
            # Calculate and mark elbow point
            self._mark_elbow_point(ax, elbow_data['k_values'], elbow_data['scores'])
        
        # Silhouette Method
        if 'silhouette' in results:
            ax = axes[0, 1]
            silhouette_data = results['silhouette']
            ax.plot(silhouette_data['k_values'], silhouette_data['scores'], 'ro-')
            ax.set_xlabel('Number of Clusters (k)')
            ax.set_ylabel('Silhouette Score')
            ax.set_title('Silhouette Method')
            ax.grid(True, alpha=0.3)
            
            # Mark optimal point
            optimal_k = silhouette_data['k_values'][np.argmax(silhouette_data['scores'])]
            optimal_score = max(silhouette_data['scores'])
            ax.plot(optimal_k, optimal_score, 'g*', markersize=15)
            ax.annotate(f'Optimal k={optimal_k}', xy=(optimal_k, optimal_score), 
                       xytext=(optimal_k + 0.1, optimal_score + 0.02))
        
        # Calinski-Harabasz Method
        if 'calinski' in results:
            ax = axes[1, 0]
            calinski_data = results['calinski']
            ax.plot(calinski_data['k_values'], calinski_data['scores'], 'go-')
            ax.set_xlabel('Number of Clusters (k)')
            ax.set_ylabel('Calinski-Harabasz Score')
            ax.set_title('Calinski-Harabasz Method')
            ax.grid(True, alpha=0.3)
            
            # Mark optimal point
            optimal_k = calinski_data['k_values'][np.argmax(calinski_data['scores'])]
            optimal_score = max(calinski_data['scores'])
            ax.plot(optimal_k, optimal_score, 'r*', markersize=15)
            ax.annotate(f'Optimal k={optimal_k}', xy=(optimal_k, optimal_score), 
                       xytext=(optimal_k + 0.1, optimal_score))
        
        # Davies-Bouldin Method
        if 'davies' in results:
            ax = axes[1, 1]
            davies_data = results['davies']
            ax.plot(davies_data['k_values'], davies_data['scores'], 'mo-')
            ax.set_xlabel('Number of Clusters (k)')
            ax.set_ylabel('Davies-Bouldin Score')
            ax.set_title('Davies-Bouldin Method (lower is better)')
            ax.grid(True, alpha=0.3)
            
            # Mark optimal point
            optimal_k = davies_data['k_values'][np.argmin(davies_data['scores'])]
            optimal_score = min(davies_data['scores'])
            ax.plot(optimal_k, optimal_score, 'r*', markersize=15)
            ax.annotate(f'Optimal k={optimal_k}', xy=(optimal_k, optimal_score), 
                       xytext=(optimal_k + 0.1, optimal_score + 0.05))
        
        plt.tight_layout()
        plt.savefig('optimal_clusters_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        return fig
    
    def _mark_elbow_point(self, ax, k_values, scores):
        """Find and mark the elbow point using the kneedle algorithm"""
        # Simple elbow detection using angles
        nPoints = len(k_values)
        allCoord = np.vstack((k_values, scores)).T
        
        # Calculate the vector from first to last point
        firstPoint = allCoord[0]
        lastPoint = allCoord[-1]
        lineVec = lastPoint - firstPoint
        lineVecNorm = lineVec / np.sqrt(np.sum(lineVec**2))
        
        # Find the distance from each point to the line
        vecFromFirst = allCoord - firstPoint
        scalarProduct = np.sum(vecFromFirst * lineVecNorm, axis=1)
        vecFromFirstParallel = np.outer(scalarProduct, lineVecNorm)
        vecToLine = vecFromFirst - vecFromFirstParallel
        distToLine = np.sqrt(np.sum(vecToLine ** 2, axis=1))
        
        # Find the maximum distance point
        idxOfBestPoint = np.argmax(distToLine)
        
        # Mark the elbow point
        ax.plot(k_values[idxOfBestPoint], scores[idxOfBestPoint], 'g*', markersize=15)
        ax.annotate(f'Elbow at k={k_values[idxOfBestPoint]}', 
                   xy=(k_values[idxOfBestPoint], scores[idxOfBestPoint]), 
                   xytext=(k_values[idxOfBestPoint] + 0.1, scores[idxOfBestPoint]))
    
    def get_recommendation(self, results):
        """Get recommended number of clusters based on all methods"""
        recommendations = {}
        
        # Silhouette (higher is better)
        if 'silhouette' in results:
            silhouette_data = results['silhouette']
            optimal_k = silhouette_data['k_values'][np.argmax(silhouette_data['scores'])]
            recommendations['silhouette'] = optimal_k
        
        # Calinski-Harabasz (higher is better)
        if 'calinski' in results:
            calinski_data = results['calinski']
            optimal_k = calinski_data['k_values'][np.argmax(calinski_data['scores'])]
            recommendations['calinski'] = optimal_k
        
        # Davies-Bouldin (lower is better)
        if 'davies' in results:
            davies_data = results['davies']
            optimal_k = davies_data['k_values'][np.argmin(davies_data['scores'])]
            recommendations['davies'] = optimal_k
        
        # Elbow method (need to calculate)
        if 'elbow' in results:
            # Simplified elbow detection
            elbow_data = results['elbow']
            k_values = elbow_data['k_values']
            scores = elbow_data['scores']
            
            # Calculate differences
            diffs = np.diff(scores)
            diff_ratios = diffs[:-1] / diffs[1:]
            
            # Find the elbow point
            elbow_idx = np.argmax(diff_ratios) + 1
            recommendations['elbow'] = k_values[elbow_idx]
        
        # Calculate consensus
        if recommendations:
            all_recommendations = list(recommendations.values())
            mode_k = max(set(all_recommendations), key=all_recommendations.count)
            
            print("\nOptimal Clusters Recommendations:")
            for method, k in recommendations.items():
                print(f"{method.capitalize()}: {k}")
            print(f"\nConsensus recommendation: {mode_k}")
            
            return mode_k, recommendations
        
        return None, None

# Example usage with your malware detection code
def analyze_optimal_clusters(data, features):
    """Analyze optimal clusters for malware detection"""
    analyzer = OptimalClustersAnalyzer(max_clusters=10)
    
    # Find optimal clusters
    results = analyzer.find_optimal_clusters(data, features)
    
    # Plot results
    analyzer.plot_results(results)
    
    # Get recommendation
    optimal_k, recommendations = analyzer.get_recommendation(results)
    
    return optimal_k, results, recommendations

def main():
    # Configuration
    benign_files = [
        './dataset/benign/registry_data_20250502_143804.csv',
        './dataset/benign/registry_data_20250502_143620.csv',
        './dataset/benign/registry_data_20250502_143509.csv',
        './dataset/benign/registry_data_20250502_143501.csv',
        './dataset/benign/registry_data_20250502_143455.csv',
        './dataset/benign/registry_data_20250502_143445.csv'
    ]
    
    malware_files = [
        './dataset/malware/malware_registry_data_20250502_143350.csv',
        './dataset/malware/malware_registry_data_20250502_143318.csv',
        './dataset/malware/malware_registry_data_20250502_143313.csv',
        './dataset/malware/malware_registry_data_20250502_143252.csv',
        './dataset/malware/malware_registry_data_20250502_143239.csv',
        './dataset/malware/malware_registry_data_20250502_143217.csv'
    ]
    
    try:
        # Load data
        print("Loading data...")
        all_data = []
        
        # Load benign data
        for file in benign_files:
            try:
                df = pd.read_csv(file)
                df['TrueLabel'] = 'benign'
                df['SourceFile'] = file
                all_data.append(df)
            except Exception as e:
                print(f"Error loading {file}: {e}")
        
        # Load malware data
        for file in malware_files:
            try:
                df = pd.read_csv(file)
                # Mark AvosLocker processes as malware
                df['TrueLabel'] = df['ProcessName'].apply(
                    lambda x: 'malware' if 'avoslocker' in str(x).lower() else 'benign'
                )
                df['SourceFile'] = file
                all_data.append(df)
            except Exception as e:
                print(f"Error loading {file}: {e}")
        
        if not all_data:
            raise ValueError("No data files were successfully loaded")
        
        data = pd.concat(all_data, ignore_index=True)
        print(f"Loaded {len(data)} total records")
        
        # Initialize detector
        print("\nInitializing Combined Malware Detector...")
        detector = CombinedMalwareDetector(n_clusters=5)
        
        # Prepare features
        data, features = detector.prepare_features(data)
        
        # Fit model
        print("Fitting model...")
        cluster_labels = detector.fit(data, features)
        
        # Get classifications
        print("Classifying processes...")
        classifications, reasons = detector.predict(data, features)
        
        # Add results to dataframe
        data['Cluster'] = cluster_labels
        data['Classification'] = classifications
        data['DetectionReason'] = reasons
        
        # Evaluate performance
        print("\nPerformance Evaluation:")
        print("======================")
        
        # For true malware (AvosLocker)
        avoslocker_mask = data['ProcessName'].str.contains('avoslocker', case=False, na=False)
        if avoslocker_mask.any():
            avos_true = ['malware' if mask else 'benign' for mask in avoslocker_mask]
            avos_pred = [classifications[i] for i in range(len(classifications))]
            
            # Create simplified classification for evaluation
            avos_pred_binary = ['malware' if pred in ['malware', 'suspicious'] else 'benign' 
                               for pred in avos_pred]
            
            print("\nAvosLocker Detection Performance:")
            print(classification_report(avos_true, avos_pred_binary, 
                                      target_names=['benign', 'malware']))
        
        # Overall classification distribution
        print("\nOverall Classification Distribution:")
        print(pd.Series(classifications).value_counts())
        
        # Detection reasons distribution
        print("\nDetection Reasons:")
        print(pd.Series(reasons).value_counts())
        
        # Visualize results
        print("\nGenerating visualizations...")
        detector.visualize_results(data, features, classifications)
        
        # Save results
        output_file = 'combined_malware_detection_output.csv'
        data.to_csv(output_file, index=False)
        print(f"\nResults saved to: {output_file}")
        
        # Print suspicious processes
        suspicious_processes = data[data['Classification'].isin(['malware', 'suspicious'])]
        print(f"\nDetected {len(suspicious_processes)} suspicious/malicious processes")
        
        if len(suspicious_processes) > 0:
            print("\nTop 10 suspicious processes:")
            display_columns = ['ProcessName', 'Classification', 'ProcessImageEntropy', 
                             'SensitiveKeysAccessed', 'OpsPerSecond', 'DetectionReason']
            print(suspicious_processes[display_columns].head(10))
        
        return data
        
    except Exception as e:
        print(f"Error in main execution: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = main()