import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.metrics import confusion_matrix, classification_report
import warnings
warnings.filterwarnings('ignore')

def load_data(file_path):
    """
    Load registry data from CSV file.
    """
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"Data loaded successfully with shape: {df.shape}")
    return df

def preprocess_data(df):
    """
    Preprocess data for anomaly detection:
    - Handle missing values
    - Scale features
    - Select relevant features
    """
    print("\nPreprocessing data...")
    
    # Create a copy of the dataframe
    processed_df = df.copy()
    
    # Separate numeric and categorical columns
    numeric_cols = processed_df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = processed_df.select_dtypes(include=['object']).columns.tolist()
    
    print(f"Found {len(numeric_cols)} numeric columns and {len(categorical_cols)} categorical columns")
    
    # Handle missing values separately for numeric and categorical
    if numeric_cols and processed_df[numeric_cols].isnull().sum().sum() > 0:
        print("Filling missing numeric values with mean...")
        processed_df[numeric_cols] = processed_df[numeric_cols].fillna(processed_df[numeric_cols].mean())
    
    if categorical_cols and processed_df[categorical_cols].isnull().sum().sum() > 0:
        print("Filling missing categorical values with mode...")
        for col in categorical_cols:
            if processed_df[col].isnull().sum() > 0:
                processed_df[col] = processed_df[col].fillna(processed_df[col].mode()[0])
    
    # Remove the ProcessId column if it exists (it's an identifier, not a feature)
    if 'ProcessId' in numeric_cols:
        numeric_cols.remove('ProcessId')
        print("Removed ProcessId from numeric features")
    
    # Also remove time-based columns
    time_cols = ['FirstSeenTime', 'LastSeenTime', 'ProcessCreateTime']
    for col in time_cols:
        if col in numeric_cols:
            numeric_cols.remove(col)
            print(f"Removed {col} from numeric features")
    
    # Create feature dataframe with only numeric columns
    X = processed_df[numeric_cols]
    
    # Scale the features (important for K-means and anomaly detection)
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"Data preprocessed successfully with {X_scaled.shape[1]} numeric features")
    
    return X_scaled, numeric_cols, processed_df

def anomaly_detection_kmeans(X_scaled, k=20, contamination=0.1):
    """
    Perform anomaly detection using K-means clustering.
    
    The approach:
    1. Cluster the data into k clusters
    2. Calculate the distance of each point to its cluster centroid
    3. Points with large distances are considered anomalies
    
    Params:
        X_scaled: Scaled features
        k: Number of clusters
        contamination: Expected proportion of anomalies (0.1 = 10%)
    
    Returns:
        y_pred: Binary labels (1: normal, -1: anomaly)
        anomaly_scores: Distance to cluster centroid for each point
    """
    print(f"\nPerforming K-means anomaly detection with k={k}...")
    
    # Train K-means
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    kmeans.fit(X_scaled)
    
    # Get cluster labels and distances to centroids
    labels = kmeans.labels_
    centroids = kmeans.cluster_centers_
    
    # Calculate distance of each point to its assigned centroid
    distances = np.zeros(X_scaled.shape[0])
    for i in range(X_scaled.shape[0]):
        cluster_label = labels[i]
        distances[i] = np.linalg.norm(X_scaled[i] - centroids[cluster_label])
    
    # Determine threshold for anomalies
    threshold = np.percentile(distances, 100 * (1 - contamination))
    
    # Identify anomalies (points with distances > threshold)
    y_pred = np.ones(X_scaled.shape[0])
    y_pred[distances > threshold] = -1  # -1 for anomalies, 1 for normal points
    
    print(f"Identified {np.sum(y_pred == -1)} anomalies out of {X_scaled.shape[0]} samples.")
    
    return y_pred, distances, kmeans

def anomaly_detection_isolation_forest(X_scaled, contamination=0.1):
    """
    Perform anomaly detection using Isolation Forest algorithm.
    This is for comparison with the K-means method.
    
    Params:
        X_scaled: Scaled features
        contamination: Expected proportion of anomalies
    
    Returns:
        y_pred: Binary labels (1: normal, -1: anomaly)
        anomaly_scores: Anomaly scores from Isolation Forest
    """
    print("\nPerforming Isolation Forest anomaly detection for comparison...")
    
    # Train Isolation Forest
    isolation_forest = IsolationForest(contamination=contamination, random_state=42)
    y_pred = isolation_forest.fit_predict(X_scaled)
    anomaly_scores = isolation_forest.decision_function(X_scaled)
    
    # Convert scores for consistency (higher score = more anomalous)
    anomaly_scores = -anomaly_scores
    
    print(f"Identified {np.sum(y_pred == -1)} anomalies out of {X_scaled.shape[0]} samples.")
    
    return y_pred, anomaly_scores

def anomaly_detection_local_outlier_factor(X_scaled, n_neighbors=20, contamination=0.1):
    """
    Perform anomaly detection using distance to k-nearest neighbors.
    A simple implementation of an approach similar to Local Outlier Factor.
    
    Params:
        X_scaled: Scaled features
        n_neighbors: Number of neighbors to consider
        contamination: Expected proportion of anomalies
    
    Returns:
        y_pred: Binary labels (1: normal, -1: anomaly)
        anomaly_scores: Average distance to nearest neighbors
    """
    print(f"\nPerforming Nearest Neighbors anomaly detection with n_neighbors={n_neighbors}...")
    
    # Train Nearest Neighbors
    nn = NearestNeighbors(n_neighbors=n_neighbors)
    nn.fit(X_scaled)
    
    # Get distances to k-nearest neighbors
    distances, _ = nn.kneighbors(X_scaled)
    
    # Use average distance to k-nearest neighbors as anomaly score
    anomaly_scores = np.mean(distances, axis=1)
    
    # Determine threshold for anomalies
    threshold = np.percentile(anomaly_scores, 100 * (1 - contamination))
    
    # Identify anomalies
    y_pred = np.ones(X_scaled.shape[0])
    y_pred[anomaly_scores > threshold] = -1  # -1 for anomalies, 1 for normal points
    
    print(f"Identified {np.sum(y_pred == -1)} anomalies out of {X_scaled.shape[0]} samples.")
    
    return y_pred, anomaly_scores

def visualize_anomalies(X_scaled, y_pred, distances, method_name="K-means"):
    """
    Visualize the detected anomalies using PCA for dimensionality reduction.
    
    Params:
        X_scaled: Scaled features
        y_pred: Binary labels (1: normal, -1: anomaly)
        distances: Anomaly scores
        method_name: Name of the anomaly detection method
    """
    print(f"\nVisualizing anomalies detected by {method_name}...")
    
    # Apply PCA to reduce to 2 dimensions for visualization
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    
    # Plot normal vs anomaly points
    plt.figure(figsize=(12, 10))
    
    # Plot normal points
    plt.scatter(
        X_pca[y_pred == 1, 0], 
        X_pca[y_pred == 1, 1], 
        c='blue', 
        label='Normal',
        alpha=0.5,
        s=30
    )
    
    # Plot anomaly points
    plt.scatter(
        X_pca[y_pred == -1, 0], 
        X_pca[y_pred == -1, 1], 
        c='red', 
        label='Anomaly',
        alpha=0.7,
        s=50
    )
    
    plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
    plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
    plt.title(f'Anomaly Detection using {method_name}')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(f'anomaly_detection_{method_name.lower().replace(" ", "_")}.png')
    print(f"Anomaly visualization saved to 'anomaly_detection_{method_name.lower().replace(' ', '_')}.png'")
    
    # Create a scatter plot colored by anomaly score
    plt.figure(figsize=(12, 10))
    scatter = plt.scatter(
        X_pca[:, 0], 
        X_pca[:, 1], 
        c=distances, 
        cmap='viridis_r',
        alpha=0.7,
        s=40
    )
    plt.colorbar(scatter, label='Anomaly Score')
    plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
    plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
    plt.title(f'Anomaly Scores using {method_name}')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(f'anomaly_scores_{method_name.lower().replace(" ", "_")}.png')
    print(f"Anomaly scores visualization saved to 'anomaly_scores_{method_name.lower().replace(' ', '_')}.png'")
    
    return X_pca

def analyze_anomalies(df, numeric_cols, y_pred, distances, method_name="K-means"):
    """
    Analyze the characteristics of detected anomalies.
    
    Params:
        df: Original dataframe
        numeric_cols: Numeric columns used for anomaly detection
        y_pred: Binary labels (1: normal, -1: anomaly)
        distances: Anomaly scores
        method_name: Name of the anomaly detection method
    """
    print(f"\nAnalyzing anomalies detected by {method_name}...")
    
    # Add anomaly information to the dataframe
    df_with_anomalies = df.copy()
    df_with_anomalies['IsAnomaly'] = y_pred == -1
    df_with_anomalies['AnomalyScore'] = distances
    
    # Separate normal and anomaly data
    normal_df = df_with_anomalies[~df_with_anomalies['IsAnomaly']]
    anomaly_df = df_with_anomalies[df_with_anomalies['IsAnomaly']]
    
    print(f"Number of normal samples: {len(normal_df)}")
    print(f"Number of anomaly samples: {len(anomaly_df)}")
    
    # Compare feature distributions between normal and anomaly samples
    compare_data = []
    
    for col in numeric_cols:
        if col in df.columns:
            normal_mean = normal_df[col].mean()
            anomaly_mean = anomaly_df[col].mean() if len(anomaly_df) > 0 else 0
            percent_diff = ((anomaly_mean - normal_mean) / normal_mean * 100) if normal_mean != 0 else 0
            
            compare_data.append({
                'Feature': col,
                'Normal Mean': normal_mean,
                'Anomaly Mean': anomaly_mean,
                'Percent Difference': percent_diff
            })
    
    compare_df = pd.DataFrame(compare_data)
    compare_df = compare_df.sort_values('Percent Difference', ascending=False)
    
    # Save comparison to CSV
    compare_df.to_csv(f'anomaly_features_{method_name.lower().replace(" ", "_")}.csv', index=False)
    print(f"Anomaly feature comparison saved to 'anomaly_features_{method_name.lower().replace(' ', '_')}.csv'")
    
    # Print top distinctive features
    print("\nTop features distinguishing anomalies from normal samples:")
    for _, row in compare_df.head(10).iterrows():
        print(f"{row['Feature']}: Normal={row['Normal Mean']:.2f}, Anomaly={row['Anomaly Mean']:.2f}, Diff={row['Percent Difference']:.2f}%")
    
    # Visualize top distinctive features
    top_features = compare_df.head(10)['Feature'].tolist()
    
    # Only visualize if we have anomalies
    if len(anomaly_df) > 0:
        plt.figure(figsize=(15, 12))
        for i, feature in enumerate(top_features[:min(len(top_features), 6)]):
            plt.subplot(2, 3, i+1)
            sns.histplot(normal_df[feature], color='blue', alpha=0.5, label='Normal', kde=True)
            sns.histplot(anomaly_df[feature], color='red', alpha=0.5, label='Anomaly', kde=True)
            plt.title(feature)
            plt.legend()
        
        plt.tight_layout()
        plt.savefig(f'anomaly_feature_distributions_{method_name.lower().replace(" ", "_")}.png')
        print(f"Anomaly feature distributions saved to 'anomaly_feature_distributions_{method_name.lower().replace(' ', '_')}.png'")
    
    # Save the data with anomaly information
    df_with_anomalies.to_csv(f'registry_data_with_anomalies_{method_name.lower().replace(" ", "_")}.csv', index=False)
    print(f"Data with anomaly information saved to 'registry_data_with_anomalies_{method_name.lower().replace(' ', '_')}.csv'")
    
    return df_with_anomalies, compare_df

def compare_methods(df, kmeans_pred, isolation_forest_pred, lof_pred):
    """
    Compare the results of different anomaly detection methods.
    
    Params:
        df: Original dataframe
        kmeans_pred: Predictions from K-means
        isolation_forest_pred: Predictions from Isolation Forest
        lof_pred: Predictions from Local Outlier Factor
    """
    print("\nComparing anomaly detection methods...")
    
    # Create a dataframe with predictions from all methods
    comparison_df = pd.DataFrame({
        'KMeans': kmeans_pred == -1,
        'IsolationForest': isolation_forest_pred == -1,
        'NearestNeighbors': lof_pred == -1
    })
    
    # Calculate agreement between methods
    agreement = pd.DataFrame(index=['KMeans', 'IsolationForest', 'NearestNeighbors'],
                             columns=['KMeans', 'IsolationForest', 'NearestNeighbors'],
                             dtype=float)
    
    methods = ['KMeans', 'IsolationForest', 'NearestNeighbors']
    
    for i, method1 in enumerate(methods):
        for j, method2 in enumerate(methods):
            if i == j:
                agreement.loc[method1, method2] = 1.0
            else:
                # Calculate agreement as percentage of samples where both methods agree
                agree = float(np.mean(comparison_df[method1] == comparison_df[method2]))
                agreement.loc[method1, method2] = agree
    
    print("\nAgreement between methods (percentage of samples where methods agree):")
    print(agreement)
    
    # Visualize agreement with a heatmap
    plt.figure(figsize=(10, 8))
    sns.heatmap(agreement.astype(float), annot=True, cmap='viridis', vmin=0, vmax=1)
    plt.title('Agreement Between Anomaly Detection Methods')
    plt.tight_layout()
    plt.savefig('method_agreement.png')
    print("Method agreement visualization saved to 'method_agreement.png'")
    
    # Count samples identified as anomalies by different combinations of methods
    combination_counts = {}
    
    # All methods agree (anomaly)
    all_agree_anomaly = np.logical_and.reduce([
        comparison_df['KMeans'],
        comparison_df['IsolationForest'],
        comparison_df['NearestNeighbors']
    ])
    combination_counts['All Methods'] = np.sum(all_agree_anomaly)
    
    # Identified only by specific methods
    only_kmeans = np.logical_and.reduce([
        comparison_df['KMeans'],
        ~comparison_df['IsolationForest'],
        ~comparison_df['NearestNeighbors']
    ])
    combination_counts['Only KMeans'] = np.sum(only_kmeans)
    
    only_isolation = np.logical_and.reduce([
        ~comparison_df['KMeans'],
        comparison_df['IsolationForest'],
        ~comparison_df['NearestNeighbors']
    ])
    combination_counts['Only IsolationForest'] = np.sum(only_isolation)
    
    only_lof = np.logical_and.reduce([
        ~comparison_df['KMeans'],
        ~comparison_df['IsolationForest'],
        comparison_df['NearestNeighbors']
    ])
    combination_counts['Only NearestNeighbors'] = np.sum(only_lof)
    
    # Create a bar chart of combination counts
    plt.figure(figsize=(12, 6))
    plt.bar(combination_counts.keys(), combination_counts.values())
    plt.xlabel('Method Combination')
    plt.ylabel('Number of Anomalies')
    plt.title('Anomalies Identified by Different Method Combinations')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('method_combination_counts.png')
    print("Method combination counts visualization saved to 'method_combination_counts.png'")
    
    # Add a "ConsensusAnomaly" column to the dataframe
    # An anomaly is a consensus anomaly if at least 2 methods identify it as such
    df['KMeansAnomaly'] = kmeans_pred == -1
    df['IsolationForestAnomaly'] = isolation_forest_pred == -1
    df['NearestNeighborsAnomaly'] = lof_pred == -1
    
    anomaly_count = df['KMeansAnomaly'].astype(int) + \
                    df['IsolationForestAnomaly'].astype(int) + \
                    df['NearestNeighborsAnomaly'].astype(int)
    
    df['ConsensusAnomaly'] = anomaly_count >= 2
    df['AnomalyCount'] = anomaly_count
    
    # Save the consensus results
    df.to_csv('registry_data_with_consensus_anomalies.csv', index=False)
    print("Consensus anomaly results saved to 'registry_data_with_consensus_anomalies.csv'")
    
    return df, agreement, combination_counts

def evaluate_with_labels(df, y_pred, label_column='Label'):
    """
    Evaluate anomaly detection results if labels are available.
    
    Params:
        df: Original dataframe
        y_pred: Predicted labels (1: normal, -1: anomaly)
        label_column: Column name for true labels
    """
    if label_column in df.columns:
        print("\nEvaluating anomaly detection with labeled data...")
        
        # Convert labels to binary (assuming malware=1, benign=0)
        y_true = df[label_column].copy()
        
        # Convert anomaly predictions to match label format (anomaly=-1 -> malware=1)
        y_pred_converted = (y_pred == -1).astype(int)
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_true, y_pred_converted)
        
        # Calculate metrics
        tn, fp, fn, tp = cm.ravel()
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        print("\nConfusion Matrix:")
        print(cm)
        print(f"\nAccuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        
        # Print classification report
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred_converted))
        
        # Visualize confusion matrix
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Benign', 'Malware'],
                    yticklabels=['Benign', 'Malware'])
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Confusion Matrix')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png')
        print("Confusion matrix visualization saved to 'confusion_matrix.png'")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'confusion_matrix': cm
        }
    else:
        print("No labeled data available for evaluation.")
        return None

def analyze_malware_indicators(df, is_anomaly):
    """
    Analyze which malware indicators are most prevalent in detected anomalies.
    
    Params:
        df: Original dataframe
        is_anomaly: Boolean array indicating which samples are anomalies
    """
    print("\nAnalyzing malware indicators in detected anomalies...")
    
    # Define known malware indicators from registry features
    malware_indicators = [
        'FileExtensionModificationCount',
        'SecuritySettingModificationCount',
        'AutorunKeysAccessed',
        'SecurityKeysAccessed',
        'SensitiveKeysAccessed',
        'ProcessHijackKeysAccessed',
        'DllHijackKeysAccessed',
        'WritesToReadsRatio',
        'RegistryValueEntropyAvg',
        'ComRegistryModifications',
        'CriticalSystemKeyModifications'
    ]
    
    # Filter to indicators present in dataframe
    available_indicators = [ind for ind in malware_indicators if ind in df.columns]
    
    if not available_indicators:
        print("No known malware indicators available in the dataset.")
        return None
    
    # Calculate mean values for normal vs anomalous samples
    anomaly_df = df[is_anomaly]
    normal_df = df[~is_anomaly]
    
    if len(anomaly_df) == 0:
        print("No anomalies detected to analyze.")
        return None
    
    # Create comparison dataframe
    comparison = []
    
    for indicator in available_indicators:
        anomaly_mean = anomaly_df[indicator].mean()
        normal_mean = normal_df[indicator].mean()
        
        # Calculate how many times higher the indicator is in anomalies vs normal
        ratio = anomaly_mean / normal_mean if normal_mean > 0 else float('inf')
        
        comparison.append({
            'Indicator': indicator,
            'Normal Mean': normal_mean,
            'Anomaly Mean': anomaly_mean,
            'Ratio': ratio
        })
    
    comparison_df = pd.DataFrame(comparison)
    comparison_df = comparison_df.sort_values('Ratio', ascending=False)
    
    # Print results
    print("\nMalware indicators ranked by prevalence in anomalies vs normal samples:")
    for _, row in comparison_df.iterrows():
        ratio_str = f"{row['Ratio']:.2f}x" if not np.isinf(row['Ratio']) else "∞"
        print(f"{row['Indicator']}: {ratio_str} higher in anomalies")
    
    # Visualize top indicators
    plt.figure(figsize=(12, 8))
    top_indicators = comparison_df.head(min(len(comparison_df), 10))
    
    bars = plt.barh(top_indicators['Indicator'], top_indicators['Ratio'])
    plt.xlabel('Ratio (Anomaly Mean / Normal Mean)')
    plt.ylabel('Malware Indicator')
    plt.title('Top Malware Indicators in Detected Anomalies')
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Add value labels to bars
    for bar in bars:
        width = bar.get_width()
        if np.isinf(width):
            plt.text(100, bar.get_y() + bar.get_height()/2, '∞', ha='left', va='center')
        else:
            plt.text(width + 0.3, bar.get_y() + bar.get_height()/2, f'{width:.1f}x', ha='left', va='center')
    
    plt.tight_layout()
    plt.savefig('malware_indicators.png')
    print("Malware indicator analysis saved to 'malware_indicators.png'")
    
    return comparison_df

def main():
    """
    Main function to orchestrate the anomaly detection analysis.
    """
    print("Registry Data K-Means Anomaly Detection")
    print("======================================\n")
    
    # 1. Load data
    file_path = "registry_data_20250430_115714.csv"  # Replace with your actual file path
    df = load_data(file_path)
    
    # 2. Preprocess data
    X_scaled, numeric_cols, processed_df = preprocess_data(df)
    
    # 3. Set contamination (expected proportion of anomalies)
    contamination = 0.1  # 10% of data expected to be anomalies
    
    # 4. Perform K-means anomaly detection
    kmeans_pred, kmeans_scores, kmeans_model = anomaly_detection_kmeans(X_scaled, k=20, contamination=contamination)
    
    # 5. Visualize and analyze K-means results
    visualize_anomalies(X_scaled, kmeans_pred, kmeans_scores, method_name="K-means")
    df_with_kmeans, kmeans_comparison = analyze_anomalies(processed_df, numeric_cols, kmeans_pred, kmeans_scores, method_name="K-means")
    
    # 6. Perform Isolation Forest anomaly detection for comparison
    isolation_forest_pred, isolation_forest_scores = anomaly_detection_isolation_forest(X_scaled, contamination=contamination)
    
    # 7. Visualize and analyze Isolation Forest results
    visualize_anomalies(X_scaled, isolation_forest_pred, isolation_forest_scores, method_name="Isolation Forest")
    df_with_isolation, isolation_comparison = analyze_anomalies(processed_df, numeric_cols, isolation_forest_pred, isolation_forest_scores, method_name="Isolation Forest")
    
    # 8. Perform Nearest Neighbors anomaly detection for comparison
    lof_pred, lof_scores = anomaly_detection_local_outlier_factor(X_scaled, n_neighbors=20, contamination=contamination)
    
    # 9. Visualize and analyze Nearest Neighbors results
    visualize_anomalies(X_scaled, lof_pred, lof_scores, method_name="Nearest Neighbors")
    df_with_lof, lof_comparison = analyze_anomalies(processed_df, numeric_cols, lof_pred, lof_scores, method_name="Nearest Neighbors")
    
    # 10. Compare the different methods
    df_with_consensus, method_agreement, combination_counts = compare_methods(processed_df, kmeans_pred, isolation_forest_pred, lof_pred)
    
    # 11. Evaluate with labeled data if available
    # Uncomment if you have labeled data
    # kmeans_evaluation = evaluate_with_labels(processed_df, kmeans_pred, label_column='Label')
    
    # 12. Analyze malware indicators in consensus anomalies
    indicator_analysis = analyze_malware_indicators(df_with_consensus, df_with_consensus['ConsensusAnomaly'])
    
    print("\nAnomaly detection analysis complete!")

if __name__ == "__main__":
    main()