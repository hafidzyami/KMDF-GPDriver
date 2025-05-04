import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, accuracy_score
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

# 1. Load registry data
def load_data(file_path):
    """
    Load registry data from CSV file.
    """
    print(f"Loading data from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"Data loaded successfully with shape: {df.shape}")
    return df

# 2. Exploratory Data Analysis (EDA)
def perform_eda(df):
    """
    Perform basic exploratory data analysis.
    """
    print("\nPerforming Exploratory Data Analysis...\n")
    
    # Basic statistics
    print("Basic statistics:")
    print(f"Number of samples: {df.shape[0]}")
    print(f"Number of features: {df.shape[1]}")
    
    # Check for missing values
    missing_values = df.isnull().sum().sum()
    print(f"Total missing values: {missing_values}")
    
    if missing_values > 0:
        print("Columns with missing values:")
        print(df.isnull().sum()[df.isnull().sum() > 0])
    
    # Check data types
    print("\nData types:")
    print(df.dtypes.value_counts())
    
    # Feature distribution - histograms for a few key features
    key_features = [
        'TotalOperationCount', 'ProcessImageEntropy', 
        'RegistryValueEntropyAvg', 'WritesToReadsRatio',
        'OperationDensityPerMin'
    ]
    
    available_features = [f for f in key_features if f in df.columns]
    
    if available_features:
        plt.figure(figsize=(15, 10))
        for i, feature in enumerate(available_features):
            plt.subplot(2, 3, i+1)
            sns.histplot(df[feature], kde=True)
            plt.title(f'Distribution of {feature}')
        plt.tight_layout()
        plt.savefig('feature_distributions.png')
        print("Feature distributions saved to 'feature_distributions.png'")
    
    return df

# 3. Data Preprocessing
def preprocess_data(df):
    """
    Preprocess data for clustering:
    - Handle missing values
    - Scale features
    - Optionally encode categorical variables
    """
    print("\nPreprocessing data...")
    
    # Create a copy of the dataframe
    processed_df = df.copy()
    
    # Get column types
    numeric_cols = processed_df.select_dtypes(include=['number']).columns.tolist()
    categorical_cols = processed_df.select_dtypes(include=['object']).columns.tolist()
    
    print(f"Found {len(numeric_cols)} numeric columns and {len(categorical_cols)} categorical columns")
    
    # Handle missing values separately for numeric and categorical columns
    if processed_df[numeric_cols].isnull().sum().sum() > 0:
        print("Filling missing numeric values with mean...")
        processed_df[numeric_cols] = processed_df[numeric_cols].fillna(processed_df[numeric_cols].mean())
    
    if processed_df[categorical_cols].isnull().sum().sum() > 0:
        print("Filling missing categorical values with mode...")
        for col in categorical_cols:
            if processed_df[col].isnull().sum() > 0:
                processed_df[col] = processed_df[col].fillna(processed_df[col].mode()[0])
    
    # Remove the ProcessId column from numeric columns if it exists (it's an identifier, not a feature)
    if 'ProcessId' in numeric_cols:
        numeric_cols.remove('ProcessId')
        print("Removed ProcessId from numeric features")
    
    # Also remove any time-based columns that might be in Unix timestamp format
    time_cols = ['FirstSeenTime', 'LastSeenTime', 'ProcessCreateTime']
    for col in time_cols:
        if col in numeric_cols:
            numeric_cols.remove(col)
            print(f"Removed {col} from numeric features")
    
    # Create feature dataframe with only numeric columns
    X = processed_df[numeric_cols]
    
    # Scale the features (important for K-means)
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"Data preprocessed successfully with {X_scaled.shape[1]} numeric features")
    
    return X_scaled, numeric_cols, processed_df

# 4. Find optimal K using Elbow Method
def find_optimal_k(X_scaled, max_k=30):
    """
    Find the optimal number of clusters using the Elbow Method.
    """
    print("\nFinding optimal number of clusters using Elbow Method...")
    
    distortions = []
    silhouette_scores = []
    K_range = range(2, max_k+1)
    
    for k in K_range:
        print(f"Testing k={k}...")
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        kmeans.fit(X_scaled)
        distortions.append(kmeans.inertia_)
        
        # Calculate Silhouette Score
        if k > 1:  # Silhouette score requires at least 2 clusters
            silhouette_scores.append(silhouette_score(X_scaled, kmeans.labels_))
    
    # Plot the Elbow Method graph
    plt.figure(figsize=(12, 5))
    
    # Distortion plot
    plt.subplot(1, 2, 1)
    plt.plot(list(K_range), distortions, 'bo-')
    plt.xlabel('Number of clusters (k)')
    plt.ylabel('Distortion (Inertia)')
    plt.title('Elbow Method for Optimal k')
    plt.grid(True)
    
    # Silhouette score plot
    plt.subplot(1, 2, 2)
    # This is crucial - the silhouette score was computed for k=2 and above,
    # but we need to make sure we're using the right x values for plotting
    silhouette_k_range = list(K_range)
    plt.plot(silhouette_k_range, silhouette_scores, 'ro-')
    plt.xlabel('Number of clusters (k)')
    plt.ylabel('Silhouette Score')
    plt.title('Silhouette Score Method for Optimal k')
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('optimal_k.png')
    print("Elbow method graph saved to 'optimal_k.png'")
    
    # Find the optimal k using the Elbow method (where the rate of decrease in distortion slows)
    # Calculate the rate of decrease
    deltas = np.array([distortions[i] - distortions[i+1] for i in range(len(distortions)-1)])
    deltas_percent = deltas / distortions[:-1] * 100
    
    # Find where the rate of improvement drops below a threshold (e.g., 10%)
    threshold = 10
    optimal_k_indices = np.where(deltas_percent < threshold)[0]
    optimal_k = K_range[optimal_k_indices[0]] if len(optimal_k_indices) > 0 else 20
    
    # Also consider silhouette score
    best_silhouette_idx = np.argmax(silhouette_scores)
    best_silhouette_k = list(K_range)[best_silhouette_idx]
    
    print(f"Suggested optimal k from Elbow method: {optimal_k}")
    print(f"Suggested optimal k from Silhouette score: {best_silhouette_k}")
    
    # If the results differ significantly, prefer silhouette score which is more reliable
    if abs(optimal_k - best_silhouette_k) > 5:
        print(f"Using Silhouette score recommendation: k={best_silhouette_k}")
        return best_silhouette_k
    else:
        return optimal_k

# 5. Perform K-means clustering
def perform_kmeans(X_scaled, k=20):
    """
    Perform K-means clustering with the specified k.
    """
    print(f"\nPerforming K-means clustering with k={k}...")
    
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    cluster_labels = kmeans.fit_predict(X_scaled)
    
    print(f"Clustering completed. Cluster sizes:")
    for i in range(k):
        print(f"Cluster {i}: {np.sum(cluster_labels == i)} samples")
    
    return kmeans, cluster_labels

# 6. Visualize clusters using PCA for dimensionality reduction
def visualize_clusters(X_scaled, cluster_labels, k):
    """
    Visualize clusters using PCA to reduce to 2 dimensions.
    """
    print("\nVisualizing clusters using PCA...")
    
    # Apply PCA to reduce to 2 dimensions for visualization
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    
    # Plot clusters
    plt.figure(figsize=(12, 10))
    scatter = plt.scatter(X_pca[:, 0], X_pca[:, 1], c=cluster_labels, cmap='viridis', alpha=0.8)
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.title(f'K-means Clustering (k={k}) with PCA Visualization')
    plt.colorbar(scatter, label='Cluster')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.savefig('cluster_visualization.png')
    print("Cluster visualization saved to 'cluster_visualization.png'")
    
    return X_pca

# 7. Analyze feature importance in each cluster
def analyze_clusters(df, numeric_cols, cluster_labels, k):
    """
    Analyze characteristics of each cluster.
    """
    print("\nAnalyzing cluster characteristics...")
    
    # Add cluster labels to the dataframe
    df_with_clusters = df.copy()
    df_with_clusters['Cluster'] = cluster_labels
    
    # Calculate cluster statistics
    cluster_stats = df_with_clusters.groupby('Cluster')[numeric_cols].mean()
    
    # Identify top features that distinguish each cluster
    # Calculate z-scores to find the most distinctive features
    z_scores = (cluster_stats - cluster_stats.mean()) / cluster_stats.std()
    
    # Create a heatmap of the cluster centers
    plt.figure(figsize=(18, 12))
    sns.heatmap(z_scores, cmap='coolwarm', center=0, annot=False, fmt='.2f')
    plt.title('Cluster Centers Heatmap (Z-scores)')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig('cluster_heatmap.png')
    print("Cluster heatmap saved to 'cluster_heatmap.png'")
    
    # Print the most important features for each cluster
    print("\nTop distinguishing features for each cluster:")
    for i in range(k):
        if i in z_scores.index:  # Make sure the cluster exists
            top_features = z_scores.loc[i].abs().nlargest(5)
            print(f"\nCluster {i}:")
            for feature, score in top_features.items():
                direction = "high" if z_scores.loc[i, feature] > 0 else "low"
                print(f"  - {feature}: {direction} ({z_scores.loc[i, feature]:.2f})")
    
    return df_with_clusters, cluster_stats

# 8. Try to identify malicious vs. benign clusters
def identify_malicious_clusters(df_with_clusters, cluster_stats, k):
    """
    Try to identify which clusters might be malicious based on known malware behaviors.
    """
    print("\nAttempting to identify potentially malicious clusters...")
    
    # Define suspicious indicators - features that might indicate malicious behavior when high
    suspicious_indicators = [
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
        'CriticalSystemKeyModifications',
        'RemoteOperationCount'
    ]
    
    # Check which suspicious indicators are actually in our dataset
    available_indicators = [col for col in suspicious_indicators if col in cluster_stats.columns]
    
    if not available_indicators:
        print("No known suspicious indicators found in the dataset.")
        return None
    
    print(f"Found {len(available_indicators)} indicators for analysis: {available_indicators}")
    
    # Create a score for each cluster based on z-scores of suspicious indicators
    malicious_scores = pd.DataFrame(index=cluster_stats.index)
    malicious_scores['MaliciousScore'] = 0
    valid_indicators_count = 0
    
    for indicator in available_indicators:
        if indicator in cluster_stats.columns:
            # Check for constant values (std = 0)
            std = cluster_stats[indicator].std()
            if std == 0:
                print(f"Skipping indicator '{indicator}' because all values are identical (std=0)")
                continue
                
            # Convert to z-scores
            z = (cluster_stats[indicator] - cluster_stats[indicator].mean()) / std
            # Add to score (higher is more suspicious)
            malicious_scores['MaliciousScore'] += z
            valid_indicators_count += 1
    
    # Normalize by number of valid indicators (avoid division by zero)
    if valid_indicators_count > 0:
        malicious_scores['MaliciousScore'] /= valid_indicators_count
        print(f"Calculated scores using {valid_indicators_count} valid indicators")
    else:
        print("Warning: No valid indicators found with variance > 0")
        return None
    
    # Sort clusters by malicious score
    malicious_scores = malicious_scores.sort_values('MaliciousScore', ascending=False)
    
    print("\nClusters ranked by potential maliciousness:")
    for cluster, row in malicious_scores.iterrows():
        print(f"Cluster {cluster}: Score {row['MaliciousScore']:.2f}")
    
    # Identify potential malicious/benign clusters
    threshold = malicious_scores['MaliciousScore'].mean() + malicious_scores['MaliciousScore'].std()
    potential_malicious = malicious_scores[malicious_scores['MaliciousScore'] > threshold]
    
    if not potential_malicious.empty:
        print("\nPotentially malicious clusters:")
        for cluster in potential_malicious.index:
            print(f"- Cluster {cluster} (Score: {malicious_scores.loc[cluster, 'MaliciousScore']:.2f})")
            # Show the key statistics for this cluster
            for indicator in available_indicators:
                if indicator in cluster_stats.columns:
                    value = cluster_stats.loc[cluster, indicator]
                    mean = cluster_stats[indicator].mean()
                    print(f"  {indicator}: {value:.2f} (Overall mean: {mean:.2f})")
    else:
        print("No clusters identified as clearly malicious based on statistical analysis.")
    
    return malicious_scores


# 9. Evaluate with labeled data (if available)
def evaluate_with_labels(df, cluster_labels, label_column='Label'):
    """
    Evaluate clustering results with labeled data if available.
    """
    if label_column in df.columns:
        print("\nEvaluating clustering results with labeled data...")
        
        # Create contingency table
        contingency = pd.crosstab(df[label_column], pd.Series(cluster_labels, name='Cluster'))
        print("Contingency table (actual labels vs. cluster assignments):")
        print(contingency)
        
        # For each cluster, get the majority class
        majority_class = {}
        for cluster in range(max(cluster_labels) + 1):
            if cluster in contingency.columns:
                col = contingency[cluster]
                if not col.empty:
                    majority_class[cluster] = col.idxmax()
        
        # Create predicted labels based on majority class in each cluster
        predicted_labels = [majority_class.get(cluster, 'unknown') for cluster in cluster_labels]
        
        # Calculate accuracy
        accuracy = accuracy_score(df[label_column], predicted_labels)
        print(f"Accuracy: {accuracy:.4f}")
        
        return accuracy, contingency
    else:
        print("No labeled data available for evaluation.")
        return None, None

# 10. Main function
def main():
    """
    Main function to orchestrate the malware detection clustering process.
    """
    print("Registry Data K-Means Clustering for Malware Detection")
    print("=====================================================\n")
    
    # 1. Load data
    file_path = "registry_data_20250430_115714.csv"  # Replace with your actual file path
    df = load_data(file_path)
    
    # 2. Perform EDA
    df = perform_eda(df)
    
    # 3. Preprocess data
    X_scaled, numeric_cols, processed_df = preprocess_data(df)
    
    # 4. Find optimal k (default to 20 based on research paper)
    optimal_k = find_optimal_k(X_scaled, max_k=30)
    print(optimal_k)
    
    # 5. Perform K-means with optimal k
    kmeans, cluster_labels = perform_kmeans(X_scaled, k=optimal_k)
    
    # 6. Visualize clusters
    X_pca = visualize_clusters(X_scaled, cluster_labels, optimal_k)
    
    # 7. Analyze clusters
    df_with_clusters, cluster_stats = analyze_clusters(processed_df, numeric_cols, cluster_labels, optimal_k)
    
    # 8. Try to identify malicious clusters
    malicious_scores = identify_malicious_clusters(df_with_clusters, cluster_stats, optimal_k)
    
    # 9. Evaluate with labeled data if available
    evaluate_with_labels(processed_df, cluster_labels, label_column='Label')
    
    # 10. Save results
    df_with_clusters.to_csv('registry_data_with_clusters.csv', index=False)
    print("\nResults saved to 'registry_data_with_clusters.csv'")
    
    print("\nClustering analysis complete!")

if __name__ == "__main__":
    main()