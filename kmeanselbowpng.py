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
        self.cluster_labels_text = []  # Untuk menyimpan label teks
        
        for i, stats in self.cluster_stats.items():
            # Cluster malware: entropy tinggi + sensitive keys tinggi
            if (stats['avg_process_image_entropy'] > 315 and 
                stats['avg_sensitive_keys'] > 5000):
                self.cluster_labels_text.append('malware')
                # Malware clusters juga bisa dianggap suspicious untuk analisis
                self.suspicious_clusters.append(i)
            
            # Cluster suspicious: indikator moderate
            elif (stats['avg_process_image_entropy'] > 300 or 
                stats['avg_sensitive_keys'] > 1000):
                self.cluster_labels_text.append('suspicious')
                self.suspicious_clusters.append(i)
            
            # Cluster benign: indikator rendah
            else:
                self.cluster_labels_text.append('benign')
        
        print(f"Cluster identification: {self.cluster_labels_text}")
        print(f"Suspicious clusters: {self.suspicious_clusters}")
    
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
        
        # Create individual figures for each plot
        # 1. PCA visualization
        fig1, ax1 = plt.subplots(figsize=(8, 6))
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
        plt.tight_layout()
        plt.savefig('./img/pca_visualization.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Key features scatter
        fig2, ax2 = plt.subplots(figsize=(8, 6))
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
        plt.tight_layout()
        plt.savefig('./img/primary_detection_features.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Time-based analysis
        fig3, ax3 = plt.subplots(figsize=(8, 6))
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
        plt.tight_layout()
        plt.savefig('./img/time_based_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 4. Cluster characteristics
        fig4, ax4 = plt.subplots(figsize=(8, 6))
        cluster_df = pd.DataFrame(self.cluster_stats).T
        features_to_plot = ['avg_process_image_entropy', 'avg_sensitive_keys', 'avg_ops_per_second']
        cluster_df[features_to_plot].plot(kind='bar', ax=ax4)
        ax4.set_title('Cluster Characteristics')
        ax4.set_xlabel('Cluster')
        ax4.set_ylabel('Average Value')
        ax4.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig('./img/cluster_characteristics.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 5. Classification distribution
        fig5, ax5 = plt.subplots(figsize=(8, 6))
        class_counts = pd.Series(classifications).value_counts()
        class_counts.plot(kind='pie', autopct='%1.1f%%', ax=ax5, colors=[colors[c] for c in class_counts.index])
        ax5.set_title('Classification Distribution')
        plt.tight_layout()
        plt.savefig('./img/classification_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 6. Detection summary
        fig6, ax6 = plt.subplots(figsize=(8, 6))
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
        plt.savefig('./img/detection_summary.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Call the detailed analysis function
        self._create_detailed_analysis(data, classifications)
    
    def visualize_cluster_vs_rules(self, data, classifications):
        """Visualize differences between cluster assignment and rule-based detection"""
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Plot 1: Cluster assignment
        for i in range(self.n_clusters):
            cluster_data = data[data['Cluster'] == i]
            if i == 0:
                label = f'Cluster {i} (Benign)'
                color = 'green'
            else:
                label = f'Cluster {i} (Suspicious/Malware)'
                color = 'red' if i == 1 else 'orange'
            
            ax1.scatter(cluster_data['ProcessImageEntropy'], 
                    cluster_data['SensitiveKeysAccessed'],
                    c=color, 
                    label=label, 
                    alpha=0.6,
                    s=100)
        
        ax1.set_xlabel('Process Image Entropy')
        ax1.set_ylabel('Sensitive Keys Accessed')
        ax1.set_yscale('log')
        ax1.set_title('Cluster Assignment')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Rule-based classification
        colors_rule = {'benign': 'green', 'suspicious': 'orange', 'malware': 'red'}
        
        for class_type in colors_rule:
            mask = np.array(classifications) == class_type
            ax2.scatter(data.loc[mask, 'ProcessImageEntropy'], 
                    data.loc[mask, 'SensitiveKeysAccessed'],
                    c=colors_rule[class_type], 
                    label=class_type.capitalize(), 
                    alpha=0.6,
                    s=100)
        
        # Add threshold lines
        ax2.axvline(x=self.thresholds['entropy_high'], color='red', linestyle='--', alpha=0.7)
        ax2.axhline(y=self.thresholds['sensitive_keys_high'], color='red', linestyle='--', alpha=0.7)
        
        # Highlight points detected by Rule4
        rule4_mask = data['DetectionReason'].str.contains('Rule4', na=False)
        if rule4_mask.any():
            rule4_data = data[rule4_mask]
            ax2.scatter(rule4_data['ProcessImageEntropy'], 
                    rule4_data['SensitiveKeysAccessed'],
                    c='purple', 
                    s=200, 
                    marker='*', 
                    edgecolors='black',
                    linewidth=2,
                    label='Rule4 Detection')
            
            # Annotate Rule4 points
            for idx, row in rule4_data.iterrows():
                # Only show annotation for points in benign cluster
                if row['Cluster'] == 0:
                    ax2.annotate('Rule4: High Entropy\n(Cluster: Benign)', 
                                xy=(row['ProcessImageEntropy'], row['SensitiveKeysAccessed']),
                                xytext=(10, 10), 
                                textcoords='offset points',
                                bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.7),
                                arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))
        
        ax2.set_xlabel('Process Image Entropy')
        ax2.set_ylabel('Sensitive Keys Accessed')
        ax2.set_yscale('log')
        ax2.set_title('Rule-Based Classification')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.suptitle('Comparison: Cluster Assignment vs Rule-Based Detection', fontsize=16)
        plt.tight_layout()
        plt.savefig('cluster_vs_rules_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Create a detailed view showing why Rule4 triggered
        fig2, ax3 = plt.subplots(figsize=(10, 8))
        
        # Plot all points
        for class_type in colors_rule:
            mask = np.array(classifications) == class_type
            ax3.scatter(data.loc[mask, 'ProcessImageEntropy'], 
                    data.loc[mask, 'SensitiveKeysAccessed'],
                    c=colors_rule[class_type], 
                    label=class_type.capitalize(), 
                    alpha=0.3,
                    s=50)
        
        # Highlight Rule4 detections
        if rule4_mask.any():
            rule4_data = data[rule4_mask]
            
            # Plot Rule4 points
            ax3.scatter(rule4_data['ProcessImageEntropy'], 
                    rule4_data['SensitiveKeysAccessed'],
                    c='purple', 
                    s=300, 
                    marker='*', 
                    edgecolors='black',
                    linewidth=3,
                    label='Rule4 Detection')
            
            # Add detailed annotations
            for idx, row in rule4_data.iterrows():
                process_name = row['ProcessName'].split('\\')[-1][:20]
                annotation_text = (f"Process: {process_name}...\n"
                                f"Cluster: {row['Cluster']}\n"
                                f"Process Entropy: {row['ProcessImageEntropy']:.1f}\n"
                                f"Registry Entropy: {row['RegistryValueEntropyAvg']:.1f}\n"
                                f"Sensitive Keys: {row['SensitiveKeysAccessed']}")
                
                ax3.annotate(annotation_text, 
                            xy=(row['ProcessImageEntropy'], row['SensitiveKeysAccessed']),
                            xytext=(15, 15), 
                            textcoords='offset points',
                            bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.9),
                            arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0', lw=2))
        
        # Add threshold lines
        ax3.axvline(x=self.thresholds['entropy_high'], color='red', linestyle='--', alpha=0.7, lw=2)
        ax3.axhline(y=self.thresholds['sensitive_keys_high'], color='red', linestyle='--', alpha=0.7, lw=2)
        
        # Add threshold for registry entropy (for Rule4)
        ax3.axvline(x=self.thresholds['entropy_suspicious'], color='orange', linestyle='--', alpha=0.7, lw=2)
        
        # Set axis limits to prevent extreme values
        ax3.set_xlim(250, 350)  # Typical range for ProcessImageEntropy
        ax3.set_ylim(1, data['SensitiveKeysAccessed'].max() * 1.1)  # Handle log scale properly
        
        # Add labels for thresholds
        ax3.text(self.thresholds['entropy_high'] + 1, 10, 
                'High Entropy\nThreshold', 
                rotation=90, verticalalignment='bottom', horizontalalignment='left',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
        
        ax3.text(255, self.thresholds['sensitive_keys_high'] * 1.1, 
                'High Sensitive Keys Threshold', 
                verticalalignment='bottom', horizontalalignment='left',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
        
        # Add note about Rule4
        ax3.text(0.02, 0.98, 
                'Rule4: High Process Entropy + High Registry Entropy\n(Registry entropy not shown in this view)',
                transform=ax3.transAxes,
                verticalalignment='top',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightblue', alpha=0.8))
        
        ax3.set_xlabel('Process Image Entropy', fontsize=12)
        ax3.set_ylabel('Sensitive Keys Accessed', fontsize=12)
        ax3.set_yscale('log')
        ax3.set_title('Rule-Based Detection Details', fontsize=14)
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('rule_based_detection_detail.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Create additional plot to show registry entropy dimension
        fig3, ax4 = plt.subplots(figsize=(10, 8))
        
        # 3D-like visualization using color for registry entropy
        scatter = ax4.scatter(data['ProcessImageEntropy'], 
                            data['SensitiveKeysAccessed'],
                            c=data['RegistryValueEntropyAvg'], 
                            cmap='viridis',
                            s=100,
                            alpha=0.7)
        
        # Add colorbar
        cbar = plt.colorbar(scatter)
        cbar.set_label('Registry Value Entropy Average', rotation=270, labelpad=20)
        
        # Highlight Rule4 detections
        if rule4_mask.any():
            rule4_data = data[rule4_mask]
            ax4.scatter(rule4_data['ProcessImageEntropy'], 
                    rule4_data['SensitiveKeysAccessed'],
                    c='red', 
                    s=300, 
                    marker='*', 
                    edgecolors='black',
                    linewidth=3,
                    label='Rule4 Detection')
            
            # Annotate
            for idx, row in rule4_data.iterrows():
                ax4.annotate(f"Rule4\nRegistry Entropy: {row['RegistryValueEntropyAvg']:.1f}", 
                            xy=(row['ProcessImageEntropy'], row['SensitiveKeysAccessed']),
                            xytext=(10, 10), 
                            textcoords='offset points',
                            bbox=dict(boxstyle='round,pad=0.5', fc='red', alpha=0.7, color='white'),
                            arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0'))
        
        # Add threshold lines
        ax4.axvline(x=self.thresholds['entropy_high'], color='red', linestyle='--', alpha=0.7, lw=2)
        ax4.axhline(y=self.thresholds['sensitive_keys_high'], color='red', linestyle='--', alpha=0.7, lw=2)
        
        # Set axis limits
        ax4.set_xlim(250, 350)
        ax4.set_ylim(1, data['SensitiveKeysAccessed'].max() * 1.1)
        
        ax4.set_xlabel('Process Image Entropy', fontsize=12)
        ax4.set_ylabel('Sensitive Keys Accessed', fontsize=12)
        ax4.set_yscale('log')
        ax4.set_title('Three Dimensions of Detection (Color = Registry Entropy)', fontsize=14)
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('three_dimension_detection.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print("Generated visualization files:")
        print("1. cluster_vs_rules_comparison.png - Side by side comparison")
        print("2. rule_based_detection_detail.png - Detailed view of rule detections")
        print("3. three_dimension_detection.png - Shows registry entropy as color")
    def _create_detailed_analysis(self, data, classifications):
        """Create additional detailed analysis plots"""
        
        # 1. Feature importance based on PCA
        fig1, ax1 = plt.subplots(figsize=(8, 6))
        features_for_pca = ['ProcessImageEntropy', 'SensitiveKeysAccessed', 'RegistryValueEntropyAvg',
                        'QueryOperationCount', 'UniqueKeysAccessed', 'OpsPerSecond']
        X = data[features_for_pca].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        pca = PCA()
        pca.fit(X_scaled)
        
        feature_importance = abs(pca.components_[0])
        importance_df = pd.DataFrame({'feature': features_for_pca, 'importance': feature_importance})
        importance_df = importance_df.sort_values('importance', ascending=True)
        
        importance_df.plot(kind='barh', x='feature', y='importance', ax=ax1, legend=False)
        ax1.set_title('Feature Importance (PCA)')
        ax1.set_xlabel('Importance')
        plt.tight_layout()
        plt.savefig('./img/feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Process type distribution
        fig2, ax2 = plt.subplots(figsize=(8, 6))
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
        process_pivot.plot(kind='bar', stacked=True, ax=ax2)
        ax2.set_title('Classifications by Process Type')
        ax2.set_xlabel('Process Type')
        ax2.set_ylabel('Count')
        ax2.legend(title='Classification')
        plt.tight_layout()
        plt.savefig('./img/process_classification_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Suspicious cluster analysis
        fig3, ax3 = plt.subplots(figsize=(10, 8))
    
        print(f"Debug - Suspicious clusters: {self.suspicious_clusters}")
        print(f"Debug - Total data points: {len(data)}")
        
        if len(self.suspicious_clusters) > 0:
            suspicious_data = data[data['Cluster'].isin(self.suspicious_clusters)]
            print(f"Debug - Suspicious data shape: {suspicious_data.shape}")
            
            if len(suspicious_data) > 0:
                # Plot data dari suspicious clusters
                for cluster_id in self.suspicious_clusters:
                    cluster_data = suspicious_data[suspicious_data['Cluster'] == cluster_id]
                    if len(cluster_data) > 0:
                        print(f"Debug - Cluster {cluster_id} data points: {len(cluster_data)}")
                        print(f"Debug - Entropy range: {cluster_data['ProcessImageEntropy'].min()} - {cluster_data['ProcessImageEntropy'].max()}")
                        print(f"Debug - Sensitive keys range: {cluster_data['SensitiveKeysAccessed'].min()} - {cluster_data['SensitiveKeysAccessed'].max()}")
                        
                        ax3.scatter(cluster_data['ProcessImageEntropy'], 
                                cluster_data['SensitiveKeysAccessed'],
                                label=f'Cluster {cluster_id}',
                                alpha=0.8,
                                s=100)
                
                # Plot juga benign data untuk perbandingan
                benign_data = data[~data['Cluster'].isin(self.suspicious_clusters)]
                if len(benign_data) > 0:
                    ax3.scatter(benign_data['ProcessImageEntropy'], 
                            benign_data['SensitiveKeysAccessed'],
                            c='lightgray', 
                            label='Benign',
                            alpha=0.3,
                            s=50)
                
                ax3.set_xlabel('Process Image Entropy')
                ax3.set_ylabel('Sensitive Keys Accessed')
                ax3.set_yscale('log')
                ax3.set_title('Suspicious Clusters Analysis')
                ax3.legend()
                ax3.grid(True, alpha=0.3)
                
                # Set axis limits untuk memastikan semua data terlihat
                all_entropy = data['ProcessImageEntropy']
                all_sensitive = data['SensitiveKeysAccessed']
                ax3.set_xlim(all_entropy.min() - 10, all_entropy.max() + 10)
                ax3.set_ylim(max(1, all_sensitive.min() / 10), all_sensitive.max() * 10)
            else:
                ax3.text(0.5, 0.5, 'No data in suspicious clusters', 
                        transform=ax3.transAxes, ha='center', va='center', 
                        fontsize=14)
                ax3.set_title('Suspicious Clusters Analysis (No Data)')
        else:
            ax3.text(0.5, 0.5, 'No suspicious clusters identified', 
                    transform=ax3.transAxes, ha='center', va='center', 
                    fontsize=14)
            ax3.set_title('Suspicious Clusters Analysis (None Found)')
        
        plt.tight_layout()
        plt.savefig('./img/suspicious_clusters_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 4. Time-based patterns
        fig4, ax4 = plt.subplots(figsize=(8, 6))
        ax4.scatter(data['ProcessAgeSeconds'], data['QueryPerSecond'],
                c=[{'benign': 'green', 'suspicious': 'orange', 'malware': 'red'}[c] 
                    for c in classifications], alpha=0.6)
        ax4.set_xlabel('Process Age (seconds)')
        ax4.set_ylabel('Queries per Second')
        ax4.set_yscale('log')
        ax4.set_title('Query Rate vs Process Age')
        plt.tight_layout()
        plt.savefig('./img/query_rate_patterns.png', dpi=300, bbox_inches='tight')
        plt.close()
    
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
        
        return results
    
    def plot_results(self, results):
        """Plot results for elbow method only"""
        fig, ax = plt.subplots(figsize=(10, 8))
        
        elbow_data = results['elbow']
        ax.plot(elbow_data['k_values'], elbow_data['scores'], 'bo-', linewidth=2, markersize=10)
        ax.set_xlabel('Number of Clusters (k)', fontsize=14)
        ax.set_ylabel('Inertia', fontsize=14)
        ax.set_title('Elbow Method for Optimal k', fontsize=16)
        ax.grid(True, alpha=0.3)
        
        # Mark elbow point
        self._mark_elbow_point(ax, elbow_data['k_values'], elbow_data['scores'])
        
        # Add annotation explaining the choice
        ax.text(0.05, 0.95, f'K = {elbow_data["k_values"]}', 
                transform=ax.transAxes, fontsize=12, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow", alpha=0.5))
        
        plt.tight_layout()
        plt.savefig('./img/elbow_method_result.png', dpi=300, bbox_inches='tight')
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
    # """Analyze optimal clusters for malware detection"""
    # analyzer = OptimalClustersAnalyzer(max_clusters=10)
    
    # # Find optimal clusters
    # results = analyzer.find_optimal_clusters(data, features)
    
    # # Plot results
    # analyzer.plot_results(results)
    
    # # Get recommendation
    # optimal_k, recommendations = analyzer.get_recommendation(results)
    
    # return optimal_k, results, recommendations
    
    """Analyze optimal clusters using elbow method only"""
    analyzer = OptimalClustersAnalyzer(max_clusters=10)
    
    # Find optimal clusters using elbow method only
    results = analyzer.find_optimal_clusters(data, features, method='elbow')
    
    # Plot results
    analyzer.plot_results(results)
    
    # Get recommendation from elbow method
    elbow_data = results['elbow']
    k_values = elbow_data['k_values']
    scores = elbow_data['scores']
    
    # Calculate elbow point
    diffs = np.diff(scores)
    diff_ratios = diffs[:-1] / diffs[1:]
    elbow_idx = np.argmax(diff_ratios) + 1
    optimal_k = k_values[elbow_idx]
    
    print(f"\nElbow method recommends: k={optimal_k}")
    
    return optimal_k, results

def validate_clusters(data, cluster_labels, n_clusters=3):
    """Validate cluster assignments"""
    print("\nCluster Validation:")
    print("==================")
    
    for i in range(n_clusters):
        cluster_data = data[cluster_labels == i]
        print(f"\nCluster {i}:")
        print(f"Size: {len(cluster_data)}")
        print(f"Avg Process Entropy: {cluster_data['ProcessImageEntropy'].mean():.2f}")
        print(f"Avg Sensitive Keys: {cluster_data['SensitiveKeysAccessed'].mean():.2f}")
        print(f"Avg Registry Entropy: {cluster_data['RegistryValueEntropyAvg'].mean():.2f}")
        
        # Check for malware
        if 'ProcessName' in cluster_data.columns:
            malware_count = cluster_data['ProcessName'].str.contains('avoslocker', case=False, na=False).sum()
            print(f"Known malware count: {malware_count}")

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
        
            # Prepare features
        detector = CombinedMalwareDetector(n_clusters=2)  # Initial value
        data, features = detector.prepare_features(data)
        
        # Find optimal number of clusters
        print("Finding optimal number of clusters...")
        optimal_k, cluster_results = analyze_optimal_clusters(data, features)
        
        print("\nElbow Method Results:")
        elbow_data = cluster_results['elbow']
        print(f"k values: {elbow_data['k_values']}")
        print(f"scores: {elbow_data['scores']}")
        print(f"\nOptimal k: {optimal_k}")
        
        # Use the optimal k from elbow method
        print(f"\nUsing optimal number of clusters from elbow: {optimal_k}")
        detector = CombinedMalwareDetector(n_clusters=optimal_k)
        
        # Fit model
        print("Fitting model...")
        cluster_labels = detector.fit(data, features)
        
        # Tambahkan debug info
        print(f"Number of clusters: {detector.n_clusters}")
        print(f"Suspicious clusters: {detector.suspicious_clusters}")
        print(f"Cluster stats: {detector.cluster_stats}")

        # Cek distribusi data per cluster
        for i in range(detector.n_clusters):
            cluster_data = data[data['Cluster'] == i]
            print(f"Cluster {i}: {len(cluster_data)} samples")
        
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
        detector.visualize_cluster_vs_rules(data, classifications)
        
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