import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import warnings
warnings.filterwarnings('ignore')

def load_clustered_data(file_path='registry_data_with_clusters.csv'):
    """
    Load the data that has been clustered
    """
    print(f"Loading clustered data from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"Data loaded with shape: {df.shape}")
    return df

def analyze_registry_features_by_cluster(df):
    """
    Analyze how registry features differ between clusters.
    Focus on features related to malware behavior.
    """
    print("\nAnalyzing registry features by cluster...")
    
    # List of key registry features based on your driver
    registry_features = [
        'TotalOperationCount', 'CreateOperationCount', 'ModifyOperationCount', 
        'DeleteOperationCount', 'QueryOperationCount', 'UniqueKeysAccessed',
        'AutorunKeysAccessed', 'SecurityKeysAccessed', 'FileAssocKeysAccessed',
        'NetworkingKeysAccessed', 'ServicesKeysAccessed', 'SensitiveKeysAccessed',
        'ProcessHijackKeysAccessed', 'DllHijackKeysAccessed', 'ComObjectKeysAccessed',
        'WritesToReadsRatio', 'RegistryKeyDepthMax', 'RegistryValueEntropyAvg',
        'ComRegistryModifications', 'CriticalSystemKeyModifications'
    ]
    
    # Filter to features actually present in the dataset
    available_features = [f for f in registry_features if f in df.columns]
    
    if not available_features:
        print("No registry-specific features found in the dataset.")
        return
    
    # Create a figure to plot distributions
    plt.figure(figsize=(15, 15))
    plt.suptitle("Registry Feature Distributions by Cluster", fontsize=16)
    
    # Plot boxplots for each feature by cluster
    for i, feature in enumerate(available_features[:9]):  # Plot first 9 features
        if i < 9:  # Limit to avoid too many plots
            plt.subplot(3, 3, i+1)
            sns.boxplot(x='Cluster', y=feature, data=df)
            plt.title(f'{feature}')
            plt.xticks(rotation=90)
    
    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig('registry_features_by_cluster1.png')
    
    # If we have more features, create a second plot
    if len(available_features) > 9:
        plt.figure(figsize=(15, 15))
        plt.suptitle("Registry Feature Distributions by Cluster (Continued)", fontsize=16)
        
        for i, feature in enumerate(available_features[9:18]):  # Plot next 9 features
            if i < 9:  # Limit to avoid too many plots
                plt.subplot(3, 3, i+1)
                sns.boxplot(x='Cluster', y=feature, data=df)
                plt.title(f'{feature}')
                plt.xticks(rotation=90)
        
        plt.tight_layout(rect=[0, 0, 1, 0.97])
        plt.savefig('registry_features_by_cluster2.png')
    
    print("Registry feature distribution plots saved.")
    
    # Create a correlation matrix for the registry features
    corr_matrix = df[available_features].corr()
    
    # Plot correlation heatmap
    plt.figure(figsize=(12, 10))
    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', vmin=-1, vmax=1, fmt='.2f')
    plt.title('Correlation Matrix of Registry Features')
    plt.tight_layout()
    plt.savefig('registry_features_correlation.png')
    print("Correlation matrix of registry features saved.")
    
    return available_features

def identify_suspicious_processes(df, malicious_cluster_ids=None):
    """
    Identify potentially suspicious processes based on clustering.
    If malicious_cluster_ids is provided, use those. Otherwise,
    attempt to identify suspicious clusters based on features.
    """
    print("\nIdentifying potentially suspicious processes...")
    
    if malicious_cluster_ids is None:
        # Try to identify suspicious clusters based on key malware indicators
        suspicious_indicators = [
            'FileExtensionModificationCount', 'SecuritySettingModificationCount',
            'AutorunKeysAccessed', 'SensitiveKeysAccessed', 'ProcessHijackKeysAccessed',
            'DllHijackKeysAccessed', 'WritesToReadsRatio', 'RegistryValueEntropyAvg',
            'ComRegistryModifications', 'CriticalSystemKeyModifications'
        ]
        
        # Check which indicators are available
        available_indicators = [i for i in suspicious_indicators if i in df.columns]
        
        if not available_indicators:
            print("No suspicious indicators available for automatic identification.")
            return pd.DataFrame()
        
        # Calculate suspiciousness score for each cluster
        cluster_stats = df.groupby('Cluster')[available_indicators].mean()
        
        # Normalize values and sum them
        normalized_stats = (cluster_stats - cluster_stats.min()) / (cluster_stats.max() - cluster_stats.min())
        cluster_scores = normalized_stats.sum(axis=1)
        
        # Sort clusters by suspiciousness score
        sorted_clusters = cluster_scores.sort_values(ascending=False)
        
        print("\nClusters ranked by suspiciousness:")
        for cluster, score in sorted_clusters.items():
            print(f"Cluster {cluster}: Score {score:.2f}")
        
        # Take top 3 clusters as suspicious
        malicious_cluster_ids = sorted_clusters.head(3).index
    
    # Get processes in suspicious clusters
    suspicious_processes = df[df['Cluster'].isin(malicious_cluster_ids)]
    
    if 'ProcessName' in df.columns:
        # Count processes by name in suspicious clusters
        process_counts = suspicious_processes['ProcessName'].value_counts()
        
        print("\nMost common processes in suspicious clusters:")
        for process_name, count in process_counts.head(10).items():
            print(f"{process_name}: {count} instances")
    
    # Print summary of suspicious processes
    print(f"\nIdentified {len(suspicious_processes)} potentially suspicious processes.")
    
    # Save suspicious processes to CSV
    if not suspicious_processes.empty:
        suspicious_processes.to_csv('suspicious_processes.csv', index=False)
        print("Suspicious processes saved to 'suspicious_processes.csv'")
    
    return suspicious_processes

def visualize_feature_importance(df, available_features):
    """
    Visualize which features are most important for distinguishing clusters.
    """
    print("\nVisualizing feature importance for cluster distinction...")
    
    if 'Cluster' not in df.columns or not available_features:
        print("Cannot perform feature importance analysis: missing cluster labels or features.")
        return
    
    # Calculate feature importance based on variance between clusters
    feature_importance = {}
    
    for feature in available_features:
        # Skip if feature doesn't exist
        if feature not in df.columns:
            continue
            
        # Calculate variance of the feature across different clusters
        cluster_means = df.groupby('Cluster')[feature].mean()
        variance_between_clusters = cluster_means.var()
        
        # Higher variance means the feature is more distinguishing
        feature_importance[feature] = variance_between_clusters
    
    # Create a dataframe for plotting
    importance_df = pd.DataFrame({
        'Feature': list(feature_importance.keys()),
        'Importance': list(feature_importance.values())
    })
    
    # Sort by importance
    importance_df = importance_df.sort_values('Importance', ascending=False)
    
    # Plot feature importance
    plt.figure(figsize=(12, 8))
    bars = plt.barh(importance_df['Feature'], importance_df['Importance'])
    plt.xlabel('Variance Between Clusters')
    plt.ylabel('Feature')
    plt.title('Feature Importance for Cluster Distinction')
    plt.tight_layout()
    plt.savefig('feature_importance.png')
    print("Feature importance visualization saved to 'feature_importance.png'")
    
    # Print top features
    print("\nTop features for distinguishing clusters:")
    for idx, row in importance_df.head(10).iterrows():
        print(f"{row['Feature']}: {row['Importance']:.4f}")
    
    return importance_df

def temporal_analysis(df):
    """
    Analyze temporal patterns in the clustered data if timestamps are available.
    """
    print("\nPerforming temporal analysis...")
    
    # Check if we have timestamp fields
    time_fields = ['FirstSeenTime', 'LastSeenTime', 'ProcessCreateTime']
    available_time_fields = [field for field in time_fields if field in df.columns]
    
    if not available_time_fields:
        print("No timestamp fields available for temporal analysis.")
        return
    
    # For each available time field, analyze distribution by cluster
    for time_field in available_time_fields:
        # Convert to datetime if needed
        try:
            df[f'{time_field}_dt'] = pd.to_datetime(df[time_field], unit='s')
            
            # Plot temporal distribution by cluster
            plt.figure(figsize=(12, 6))
            for cluster in df['Cluster'].unique():
                cluster_data = df[df['Cluster'] == cluster]
                if not cluster_data.empty:
                    # Plot CDF of timestamps for this cluster
                    sns.ecdfplot(x=f'{time_field}_dt', data=cluster_data, label=f'Cluster {cluster}')
            
            plt.xlabel('Time')
            plt.ylabel('Cumulative Proportion')
            plt.title(f'Temporal Distribution of {time_field} by Cluster')
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig(f'temporal_analysis_{time_field}.png')
            print(f"Temporal analysis for {time_field} saved.")
        except:
            print(f"Could not convert {time_field} to datetime for analysis.")
    
    # Check if we can detect temporal patterns in operation density
    if 'OperationDensityPerMin' in df.columns and 'Cluster' in df.columns:
        plt.figure(figsize=(10, 6))
        sns.boxplot(x='Cluster', y='OperationDensityPerMin', data=df)
        plt.title('Operation Density by Cluster')
        plt.xlabel('Cluster')
        plt.ylabel('Operations per Minute')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.savefig('operation_density_by_cluster.png')
        print("Operation density analysis saved.")

def evaluate_clustering_quality(df):
    """
    Evaluate the quality of clustering using various metrics.
    """
    print("\nEvaluating clustering quality...")
    
    if 'Cluster' not in df.columns:
        print("No cluster labels found in the data.")
        return
    
    # Get numeric columns (excluding Cluster and other non-numeric)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    numeric_cols = [col for col in numeric_cols if col != 'Cluster']
    
    if not numeric_cols:
        print("No numeric features available for clustering quality evaluation.")
        return
    
    # Calculate Davies-Bouldin Index directly
    # (Lower is better - measures average similarity between clusters)
    try:
        from sklearn.metrics import davies_bouldin_score
        
        # Need to scale the data first
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df[numeric_cols])
        
        db_score = davies_bouldin_score(X_scaled, df['Cluster'])
        print(f"Davies-Bouldin Index: {db_score:.4f} (lower is better)")
        
        # Calculate Silhouette Score
        from sklearn.metrics import silhouette_score
        
        silhouette = silhouette_score(X_scaled, df['Cluster'])
        print(f"Silhouette Score: {silhouette:.4f} (higher is better)")
        
        # Calculate Calinski-Harabasz Index
        from sklearn.metrics import calinski_harabasz_score
        
        ch_score = calinski_harabasz_score(X_scaled, df['Cluster'])
        print(f"Calinski-Harabasz Index: {ch_score:.4f} (higher is better)")
        
        # Create a summary DataFrame of evaluation metrics
        eval_df = pd.DataFrame({
            'Metric': ['Davies-Bouldin Index', 'Silhouette Score', 'Calinski-Harabasz Index'],
            'Value': [db_score, silhouette, ch_score],
            'Interpretation': ['Lower is better', 'Higher is better', 'Higher is better']
        })
        
        eval_df.to_csv('clustering_quality_metrics.csv', index=False)
        print("Clustering quality metrics saved to 'clustering_quality_metrics.csv'")
        
    except Exception as e:
        print(f"Error in clustering quality evaluation: {str(e)}")

def visualize_3d_clusters(df):
    """
    Visualize clusters in 3D using PCA for more informative representation.
    """
    print("\nCreating 3D visualization of clusters...")
    
    try:
        # Get numeric features
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col != 'Cluster']
        
        if len(numeric_cols) < 3:
            print("Not enough numeric features for 3D visualization.")
            return
        
        # Scale the data
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df[numeric_cols])
        
        # Apply PCA to reduce to 3 dimensions
        pca = PCA(n_components=3)
        X_pca = pca.fit_transform(X_scaled)
        
        # Create a 3D scatter plot
        from mpl_toolkits.mplot3d import Axes3D
        
        fig = plt.figure(figsize=(12, 10))
        ax = fig.add_subplot(111, projection='3d')
        
        # Plot each cluster with a different color
        for cluster in sorted(df['Cluster'].unique()):
            cluster_data = X_pca[df['Cluster'] == cluster]
            ax.scatter(
                cluster_data[:, 0], 
                cluster_data[:, 1], 
                cluster_data[:, 2],
                label=f'Cluster {cluster}',
                s=30,
                alpha=0.7
            )
        
        # Add labels and legend
        ax.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%} variance)')
        ax.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%} variance)')
        ax.set_zlabel(f'PC3 ({pca.explained_variance_ratio_[2]:.2%} variance)')
        ax.set_title('3D PCA Visualization of Registry Data Clusters')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig('3d_cluster_visualization.png')
        print("3D cluster visualization saved to '3d_cluster_visualization.png'")
        
        # Create 2D projections for each pair of principal components
        fig, axes = plt.subplots(1, 3, figsize=(18, 6))
        
        # PC1 vs PC2
        for cluster in sorted(df['Cluster'].unique()):
            cluster_data = X_pca[df['Cluster'] == cluster]
            axes[0].scatter(
                cluster_data[:, 0], 
                cluster_data[:, 1],
                label=f'Cluster {cluster}',
                alpha=0.7
            )
        axes[0].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%})')
        axes[0].set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%})')
        axes[0].set_title('PC1 vs PC2')
        axes[0].grid(True, linestyle='--', alpha=0.7)
        
        # PC1 vs PC3
        for cluster in sorted(df['Cluster'].unique()):
            cluster_data = X_pca[df['Cluster'] == cluster]
            axes[1].scatter(
                cluster_data[:, 0], 
                cluster_data[:, 2],
                label=f'Cluster {cluster}',
                alpha=0.7
            )
        axes[1].set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]:.2%})')
        axes[1].set_ylabel(f'PC3 ({pca.explained_variance_ratio_[2]:.2%})')
        axes[1].set_title('PC1 vs PC3')
        axes[1].grid(True, linestyle='--', alpha=0.7)
        
        # PC2 vs PC3
        for cluster in sorted(df['Cluster'].unique()):
            cluster_data = X_pca[df['Cluster'] == cluster]
            axes[2].scatter(
                cluster_data[:, 1], 
                cluster_data[:, 2],
                label=f'Cluster {cluster}',
                alpha=0.7
            )
        axes[2].set_xlabel(f'PC2 ({pca.explained_variance_ratio_[1]:.2%})')
        axes[2].set_ylabel(f'PC3 ({pca.explained_variance_ratio_[2]:.2%})')
        axes[2].set_title('PC2 vs PC3')
        axes[2].grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        plt.savefig('2d_projections.png')
        print("2D projections saved to '2d_projections.png'")
        
        # Return the PCA results for potential further analysis
        return X_pca, pca.explained_variance_ratio_
        
    except Exception as e:
        print(f"Error in 3D visualization: {str(e)}")
        return None, None

def analyze_process_age_vs_behavior(df):
    """
    Analyze the relationship between process age and suspicious behavior.
    """
    print("\nAnalyzing relationship between process age and behavior...")
    
    # Check if we have process age data
    if 'ProcessAgeSeconds' not in df.columns or 'Cluster' not in df.columns:
        print("Process age or cluster data not available.")
        return
    
    # Create scatter plots of process age vs key registry behaviors
    behavior_metrics = [
        'TotalOperationCount', 'WritesToReadsRatio', 'RegistryValueEntropyAvg',
        'SecurityKeysAccessed', 'SensitiveKeysAccessed', 'ProcessHijackKeysAccessed'
    ]
    
    # Check which metrics are available
    available_metrics = [metric for metric in behavior_metrics if metric in df.columns]
    
    if not available_metrics:
        print("No behavior metrics available for analysis.")
        return
    
    # Create a multi-panel figure
    n_metrics = len(available_metrics)
    fig, axes = plt.subplots(1, n_metrics, figsize=(n_metrics*5, 5))
    
    # If only one metric, make axes into a list for consistent indexing
    if n_metrics == 1:
        axes = [axes]
    
    # Create scatter plots
    for i, metric in enumerate(available_metrics):
        # Plot each cluster with different color
        for cluster in sorted(df['Cluster'].unique()):
            cluster_data = df[df['Cluster'] == cluster]
            axes[i].scatter(
                cluster_data['ProcessAgeSeconds'],
                cluster_data[metric],
                label=f'Cluster {cluster}',
                alpha=0.7
            )
        
        axes[i].set_xlabel('Process Age (seconds)')
        axes[i].set_ylabel(metric)
        axes[i].set_title(f'Process Age vs {metric}')
        axes[i].grid(True, linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig('process_age_vs_behavior.png')
    print("Process age analysis saved to 'process_age_vs_behavior.png'")
    
    # Calculate correlation between process age and behavior metrics
    corr_data = []
    for metric in available_metrics:
        correlation = df['ProcessAgeSeconds'].corr(df[metric])
        corr_data.append({
            'Metric': metric,
            'Correlation with Process Age': correlation
        })
    
    corr_df = pd.DataFrame(corr_data)
    corr_df.to_csv('process_age_correlations.csv', index=False)
    print("Process age correlation data saved to 'process_age_correlations.csv'")
    
    # Print correlation summary
    print("\nCorrelation between process age and behavior metrics:")
    for _, row in corr_df.iterrows():
        print(f"{row['Metric']}: {row['Correlation with Process Age']:.4f}")
    
    return corr_df

def main():
    """
    Main function to orchestrate the analysis of clustered registry data.
    """
    print("Registry Data Cluster Analysis and Evaluation")
    print("============================================\n")
    
    # 1. Load the clustered data
    df = load_clustered_data()
    
    # 2. Analyze registry features by cluster
    available_features = analyze_registry_features_by_cluster(df)
    
    # 3. Evaluate clustering quality
    evaluate_clustering_quality(df)
    
    # 4. Visualize clusters in 3D
    visualize_3d_clusters(df)
    
    # 5. Identify potentially suspicious processes
    suspicious_processes = identify_suspicious_processes(df)
    
    # 6. Analyze process age vs behavior
    analyze_process_age_vs_behavior(df)
    
    # 7. Visualize feature importance for clusters
    visualize_feature_importance(df, available_features)
    
    # 8. Perform temporal analysis if time data is available
    temporal_analysis(df)
    
    print("\nCluster analysis complete!")

if __name__ == "__main__":
    main()