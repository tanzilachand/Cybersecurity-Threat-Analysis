# Cybersecurity Threat Detection
![Key](images/concept.jpg)

**Cybersecurity Threat Detection** is a comprehensive data analysis project for the purpose of threat detection in network traffic, the project consists of a reusable ETL pipeline, exploratory analysis and a UI based threat detection tool based in Power BI 



# ![CI logo](https://codeinstitute.s3.amazonaws.com/fullstack/ci_logo_small.png)


## Dataset Content

Link to the dataset: [Kaggle](https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection).
Dataset consists of a wide variety of intrusions simulated in a military network environment. It has created an environment to acquire raw TCP/IP dump data for a network by simulating a typical US Air Force LAN. The LAN was focused like a real environment and blasted with multiple attacks. A connection is a sequence of TCP packets starting and ending at some time duration between which data flows to and from a source IP address to a target IP address under some well-defined protocol. Also, each connection is labelled as either normal or as an attack with exactly one specific attack type. Each connection record consists of about 100 bytes.
For each TCP/IP connection, 41 quantitative and qualitative features are obtained from normal and attack data (3 qualitative and 38 quantitative features) .The class variable has two categories: Normal and Anomalous

The following table describes all columns showing their type and meaning.
 
 | Column Name                   | Type         | Description                                                                 |
|-------------------------------|-------------|----------------------------------------------------------------------------|
| duration                      | numeric     | Length of the connection in seconds                                         |
| protocol_type                 | categorical | Type of protocol (TCP, UDP, ICMP)                                          |
| service                        | categorical | Network service on the destination (HTTP, FTP, SMTP, etc.)                 |
| flag                           | categorical | Status flag of the connection (SF, S0, REJ, etc.)                           |
| src_bytes                      | numeric     | Number of bytes sent from source to destination                             |
| dst_bytes                      | numeric     | Number of bytes sent from destination to source                             |
| land                           | binary      | 1 if connection is from/to the same host/port; 0 otherwise                  |
| wrong_fragment                 | numeric     | Number of wrong fragments in the connection                                 |
| urgent                         | numeric     | Number of urgent packets                                                    |
| hot                            | numeric     | Number of “hot” indicators (suspicious activities)                          |
| num_failed_logins              | numeric     | Number of failed login attempts                                             |
| logged_in                      | binary      | 1 if successfully logged in; 0 otherwise                                     |
| num_compromised                | numeric     | Number of compromised conditions in host                                     |
| root_shell                     | binary      | 1 if root shell obtained; 0 otherwise                                        |
| su_attempted                   | binary      | 1 if `su root` command attempted; 0 otherwise                                |
| num_root                       | numeric     | Number of root accesses                                                     |
| num_file_creations             | numeric     | Number of file creation operations                                          |
| num_shells                     | numeric     | Number of shell prompts invoked                                             |
| num_access_files               | numeric     | Number of operations on access control files                                |
| is_guest_login                 | binary      | 1 if login is a guest login; 0 otherwise                                     |
| count                          | numeric     | Number of connections to the same host as the current connection in last 2 sec |
| srv_count                      | numeric     | Number of connections to the same service in last 2 sec                      |
| serror_rate                    | numeric     | % of connections with SYN errors                                            |
| srv_serror_rate                | numeric     | % of connections to same service with SYN errors                             |
| rerror_rate                    | numeric     | % of connections with REJ errors                                            |
| srv_rerror_rate                | numeric     | % of connections to same service with REJ errors                             |
| same_srv_rate                  | numeric     | % of connections to the same service                                        |
| diff_srv_rate                  | numeric     | % of connections to different services                                      |
| srv_diff_host_rate             | numeric     | % of connections to different hosts using the same service                   |
| dst_host_count                 | numeric     | Number of connections to the same destination host                           |
| dst_host_srv_count             | numeric     | Number of connections to the same service on the destination host           |
| dst_host_same_srv_rate         | numeric     | % of connections to same service on the destination host                     |
| dst_host_diff_srv_rate         | numeric     | % of connections to different services on the destination host              |
| dst_host_same_src_port_rate    | numeric     | % of connections from the same source port                                   |
| dst_host_srv_diff_host_rate    | numeric     | % of connections to different hosts using the same service                   |
| dst_host_serror_rate           | numeric     | % of connections to the host with SYN errors                                 |
| dst_host_srv_serror_rate       | numeric     | % of connections to same service on the host with SYN errors                 |
| dst_host_rerror_rate           | numeric     | % of connections to the host with REJ errors                                 |
| dst_host_srv_rerror_rate       | numeric     | % of connections to same service on the host with REJ errors                 |
| class                          | categorical | Label: normal or intrusion type (dos, probe, r2l, u2r)                       |
| service_category               | categorical | General category of the service (ftp, http, smtp, other)                     |

## Business Requirements

* The tool needs to categorise the anomalies in the network traffic
* The UI needs to be compatible with new data as this would in theory be updated daily

## Hypothesis and how to validate?
Preliminary hypotheses:
- Hypothesis 1 — Big or strange transfers often mean trouble.
  - Connections that send or receive a lot more data than usual, or use uncommon services/protocols, are more likely to be malicious.
  - How to check: Compare average/median bytes and service frequency for labeled attacks vs normal traffic and see which features separate the groups.

- Hypothesis 2 — Sudden spikes mean DoS or scanning.
  - A sudden burst of connections or many hits to the same service likely indicates a denial‑of‑service or scan.
  - How to check: Plot counts and measure how many known attacks line up with spikes.

- Hypothesis 3 — Rare service + lots of errors = reconnaissance/exploit attempts.
  - If a rarely used service shows many error responses, it may be someone probing or trying to exploit it.
  - How to check: Cross-check service types with error rates and see which combinations are common in attack labels.

- Hypothesis 4 — Unsupervised methods find unknown issues.
  -Techniques that look for outliers (isolation forest, autoencoders) will surface unusual connections that labels may have missed.
  - How to check: Run anomaly detectors, review top anomalous records manually, and compare with labeled results.

The **machine learning model** did not begin with predefined hypotheses due to limited domain knowledge about the specific cybersecurity properties in the dataset. Instead, a data-driven and exploratory approach was adopted to encourage critical thinking and insight discovery.
In line with common real-world research practices in unsupervised learning, retroactive hypothesis validation was used.
After performing preliminary clustering with K-Means and conducting a detailed exploratory analysis of the resulting clusters, several data-driven hypotheses were formulated to better understand the key factors underlying the observed groupings and the preliminary hypotheses were partly or fully supported.

- Hypothesis 1 — Big or strange transfers often mean trouble - Partially supported

Exploratory boxplots and distribution cells shows heavy right skew in src_bytes, dst_bytes, duration. Cluster profiling and cluster_medians (cluster_medians.csv) show clusters with high dst_bytes/src_bytes aligning with anomalous clusters (see Cluster 1 vs clusters flagged anomalous). High bytes appear enriched in some anomalous clusters but not all anomalies; some anomalies are scanning activities with low bytes but high error rates. So big transfers are a signal in some attack types (exfiltration, long telnet sessions), but not universal.

- Hypothesis 2 — Sudden spikes mean DoS or scanning - Partially supported / inconclusive (needs time-series checks).

There is no explicit time-indexed spike analysis The dataset includes count, srv_count, dst_host_count which are proxy indicators. Cluster 0 and cluster 3 (large anomaly clusters) have patterns compatible with scanning/DoS (lots of small packets, high error rates) — described in profiling. The clustering and proxy features hint at scanning/DoS (clusters with many short, failed attempts), but to fully confirm spikes we would need time series plots. Note: The dataset (raw or cleaned) does not contain a timestamp or event time field, so no explicit time-window spike tests were run.

- Hypothesis 3 — Rare service + lots of errors = reconnaissance/exploit attempts - Supported

Cluster profiling (model.ipynb) describes clusters where REJ/S0 flags and high rerror_rate/srv_rerror_rate coincide with rare/private services and anomalies (clusters 3 and 0).
cluster_feature_diff_scaled.csv shows error-rate features high for anomalous clusters.

- Hypothesis 4 — Unsupervised methods find unknown issues - Supported

KMeans produced tiny clusters (cluster 6 with 1 sample, cluster 2 with 8) and several anomaly-dominated clusters — clusters surfaced rare or extreme rows. Implemented use of composite score using cluster distance + silhouette + cluster flag

- Hypotheses 5 - A combined anomaly score (cluster membership + how far a record is from its cluster center + how poorly it fits the cluster) reliably finds the most critical incidents - Supported

Anomaly-scoring in the model computes anomaly_score by combining distance-to-centroid, silhouette and cluster-based anomaly flags. The composite score ranks the one critical Telnet record (cluster 6) at the top (top_anomales.csv).This combined score gives a single metric for prioritization — it surfaces severe but rare events that simple rules might miss.

- Hypothesis 6 - A small set of the most important features (in our case 20) captures most of the signal needed for clustering and monitoring — allowing faster, simpler detection pipelines - Supported

PCA explained-variance and PCA loadings in the model show that a relatively small number of components explain most variance- pca_components.csv and avg_abs_loadings provide the top feature names. Operational detection systems (and dashboards) run faster and are easier to maintain if they use fewer features. It lowers data transfer cost, improves interpretability, and helps focus on the most relevant telemetry.

- Hypothesis 7 - If a connection uses a rare or uncommon service AND has error/flag patterns like REJ or S0, it's highly likely to be reconnaissance or brute-force activity - Supported

Categorical breakdowns (cat_service_by_cluster_topk.csv, cat_flag_by_cluster_topk.csv) and cluster profiling show rare services and REJ/S0 flags concentrate in anomaly-dominated clusters (0, 3). Cluster_feature_diff_scaled.csv shows error-rate features are highly discriminative for these clusters. This produces a fast, explainable rule with high precision that SOC can implement as an early-warning filter — easy to audit and explain to management.

## Project Plan

Goal
* Build a reliable, explainable pipeline to detect and categorise network anomalies using the dataset’s many numeric features.

Approach

1. Data intake and cleaning
   * Load raw logs into a reproducible ETL notebook.
   * Handle missing values, type conversions and basic sanity checks.

2. Quantitative feature analysis (core of the work)
   * Extensive numerical exploration: distributions, outliers, correlations and per-class summaries.
   * Feature engineering focused on numeric behavior (aggregates, rates, time-window counts).
   * Use statistical tests and visualization to prioritize features for models and rules.

3. Modeling and validation
   * Use unsupervised clustering (K‑means) to group similar connections and surface anomalous clusters.
   * Evaluate cluster quality with silhouette score, Davies‑Bouldin and Calinski‑Harabasz indices, and stability across seeds.
   * Profile clusters (centroids, per‑feature summaries) and map clusters to known labels where available to assist analysts in assigning attack categories.
  
<p>
  <img src="images/pca-cluster-visual.png" alt="pca-cluster-visual.png" width="400"/>
  <img src="images/sil_plot.png" alt="sil_plot.png" width="400"/>
</p>

4. Delivery
   * Final CSVs in folder data/clean (clean data,profiles, top_anomalies, cluster summaries)
   * Move validated results and key visualizations into the Power BI dashboard.
   * Jupiter notebooks which run from top to bottom with no manual edits and produce the CSVs listed in README.

Why this order
* The dataset is heavily numeric; deep quantitative analysis determines which engineered features and models will be effective. Validation and dashboard content is built from insights and code in the notebooks.

Artifacts / outputs
* Cleaned dataset (ETL notebook) - network-intrusions-clean.csv, network-intrusions-labels.csv (Label file extracted from the cleaned dataset), network-intrusions-groups-table.csv (A groups/lookup table for eventual use by the dashboard)
* Analysis notebooks with plots and statistical tests
* Power BI dashboard pages populated with cluster visualisations and the anomaly explorer

Cluster artifacts CSVs list: scaling/transformation pipeline, K‑means centroids, cluster assignment files, cluster profiling reports and evaluation metrics
- pca_components.csv: PCA components/loadings matrix (components × features). Used to interpret principal components and select top features.
- cluster_centroids_pca.csv: Centroid coordinates for each KMeans cluster expressed in PCA component space (cluster × PC coordinates). Useful for PCA scatter overlays and cluster descriptions.
- cluster_class_crosstab.csv: Crosstab counts of class (label) vs cluster — shows how labeled classes distribute across clusters.
- cluster_class_proportions.csv: Same as crosstab but showing proportions (per-cluster fraction per class).
- cluster_medians.csv: Per-cluster medians for numeric features. Used for robust cluster profiling and effect-size calculations.
- cluster_means.csv: Per-cluster numeric means (complementary to medians).
- cluster_std.csv: Per-cluster standard deviations for numeric features (spread).
- cluster_feature_diff_scaled.csv: Scaled median differences per cluster vs global median (a MAD-like robust z/fold-change). Used to rank features per cluster by importance.
- cluster_representative_rows.csv: Example rows (nearest-to-centroid) — one representative sample per cluster to inspect realistic connection examples.
- cat_service_by_cluster_topk.csv: For service, top K categories per cluster (proportions) — shows which services dominate clusters.
- cat_flag_by_cluster_topk.csv: For flag, top K values per cluster — useful to identify REJ/S0/SF patterns.
- cat_protocol_type_by_cluster_topk.csv: For protocol_type, proportions per cluster to see TCP/UDP/ICMP distribution.
- cat_class_by_cluster_topk.csv: For class (label), top categories per cluster (gives a quick view of class dominance per cluster).
- cat_service_category_by_cluster_topk.csv: Top service_category values per cluster (a grouped service label used for dashboards).
- top_anomalies.csv: Top N rows sorted by the composite anomaly_score (distance-to-centroid + silhouette + cluster-flag).

## The rationale to map the business requirements to the Data Visualisations

Business requirements
- Categorise anomalies in network traffic (assign type).
- UI must accept daily updates and allow quick usage by analysts.

- Mapping (visuals and why it meets the requirement)
- KPI cards (total connections, alerts today, % anomalies by severity)
  - Rationale: immediate situational awareness and trending at a glance for ops.

- Service × Error heatmap (service on one axis, error rate on the other)
  - Rationale: quickly highlights rare services generating many errors — common reconnaissance signal.

  <img src="images/Heatmap-Protocol-Service.png" alt="Heatmap-Protocol-Service.png" width="400"/>

- Cluster separation visuals (silhouette plot, cluster size distribution) + cluster purity summary
  - Rationale: shows how well unsupervised grouping separates behaviours and identifies clusters enriched for known attack labels.

- Cluster profiling panel (centroid feature values, per‑feature boxplots per cluster)
  - Rationale: explains why a group of connections is considered anomalous so analysts can interpret cluster signals.

- Anomaly explorer (scatter / dimensional reduction + sample inspector)
  - Rationale: enables manual review of top anomalous clusters and discovery of novel attack patterns missed by labels.

- Filters and date refresh (service, protocol, severity, time window) + auto-refresh for daily loads
  - Rationale: supports daily ingest and lets users narrow context quickly for investigations.

Design notes
- Prioritise numeric summary visuals because the dataset is numeric-heavy — charts should default to the most informative aggregates (counts, rates, percentiles).
- Provide both automated signals (model scores) and raw-metric views so non-technical and technical stakeholders can validate alerts.

## Analysis techniques used

**Methods applied**
  - Exploratory Data Analysis: distributions, quantiles, boxplots, class‑conditional summaries and correlation matrices to identify informative numeric features and outliers.
  - Feature engineering: rate/ratio features, rolling/window counts (2s/60s windows), protocol/service grouping and one‑hot/target encoding for categorical fields.
  - Unsupervised clustering: K‑means as the primary grouping method for discovering structure and anomalous clusters; cluster profiling to characterise cluster behaviour. Alternatives evaluated: DBSCAN, Gaussian Mixture Models.
  - Explainability and validation: cluster profiling (per‑feature percentiles), silhouette plots, cluster purity against known labels, and visual cluster separation using PCA/UMAP/t‑SNE.
  - Dimensionality reduction and exploration: PCA for variance structure, UMAP/t‑SNE for visual cluster/ anomaly inspection.

  
<p>
  <img src="images/Anomaly-Normal-bar.png" alt="Anomaly vs Normal" width="400"/>
  <img src="images/Attack-Type-Bar.png" alt="Attack Type Distribution" width="400"/>
</p>

<p>
  <img src="images/Boxplot-Distribution.png" alt="Feature Distribution Boxplot" width="400"/>
  <img src="images/Feature-Correlation-Matrix.png" alt="Feature Correlation Matrix" width="400"/>
</p>

<p>
  <img src="images/Heatmap-Protocol-Service.png" alt="Heatmap-Protocol-Service.png" width="400"/>
  <img src="images/percentage-bar-chart.png" alt="percentage-bar-chart.png" width="400"/>
</p>
 
## Dashboard Design

* List all dashboard pages and their content, either blocks of information or widgets, like buttons, checkboxes, images, or any other item that your dashboard library supports.
* Later, during the project development, you may revisit your dashboard plan to update a given feature (for example, at the beginning of the project you were confident you would use a given plot to display an insight but subsequently you used another plot type).
* How were data insights communicated to technical and non-technical audiences?
* Explain how the dashboard was designed to communicate complex data insights to different audiences. 

## Unfixed Bugs

- No critical bugs in the project. Minor issues, such as occasional warnings from pandas or matplotlib, were not fixed as they do not affect results or usability.

## Future improvements

- Produce IsolationForest scores and precision-k validation to confirm anomaly ranking — Train an IsolationForest on the same scaled numeric features
- Add event timestamps to the pipeline and produce time-window spike aggregates
- Try training alternative anomaly detectors (IsolationForest, LOF, autoencoder, and optionally a supervised RandomForest) and compare their precision-k/recall-k and rank correlations against the composite score to choose the most reliable operational scorer.

### Development Roadmap

**Challenges faced and strategies used:**
- Integrating diverse data sources and cleaning complex network logs required robust ETL pipeline and careful feature examination. Strategies included using pandas for flexible data manipulation, building reusable cleaning functions, and validating each transformation step with visual and statistical checks.
- Ensuring model explainability and operational relevance was challenging due to the high dimensionality and technical nature of the features. To address this, the team prioritized readable column naming, grouped features by operational meaning, and created summary tables and visualizations that mapped technical metrics to business-relevant insights.
- Due to the high-dimensional and complex nature of the dataset, the model development did not begin with predefined hypotheses. Instead, a data-driven approach was chosen — starting with preliminary clustering using K-Means to explore natural groupings within the data.
After identifying the clusters, a deep analytical review was conducted to interpret their characteristics and uncover potential patterns.
To enhance the understanding of these findings, ChatGPT was engaged to simulate stakeholder Persona (see Stakeholders & Personas)and provide context-driven insights into what factors might explain the observed groupings.

**New skills and tools to learn next:**
- Advanced dashboarding and automation in Power BI, including custom visuals and real-time data refresh.
- Deepening knowledge of unsupervised learning methods (e.g., KMeans, DBSCAN, autoencoders) and their application to cybersecurity anomaly detection. 
- Exploring cloud-based deployment and scaling of analysis pipelines (e.g., Azure ML, AWS SageMaker).
- Improving collaboration and reproducibility with tools like DVC (Data Version Control) and enhanced Git workflows.

## Stakeholders & Personas

**Cheit Geepity, Cybersecurity Strategy Lead**
I’ve reviewed your clustering output, and I can see why you're asking for more information regarding groupings — the clusters aren't immediately intuitive. But they do tell a story. Here's how I’d interpret them from a strategic threat detection lens:

- **Cluster 0** (7001 samples, ~99.7% anomalies):
Almost entirely anomalies. The top features are error rates (serror_rate, srv_serror_rate) and same_srv_rate. Protocol is almost all TCP, top services are private, telnet, ftp_data, and the flag S0. This looks like failed TCP connection attempts, likely probing or scanning activity.

- **Cluster 1** (10147 samples, ~3.3% anomalies):
Mostly normal traffic. Top features: dst_bytes, dst_host_count, logged_in. Protocol mostly TCP, service mostly HTTP, flag SF. This is typical web traffic, mostly benign.

- **Cluster 2** (8 samples, 0% anomalies):
All normal, features include num_root and num_compromised—but only 8 samples. Protocol TCP, service Telnet. Could be rare, long remote sessions, low priority.

- **Cluster 3** (2971 samples, ~82% anomalies):
High anomaly rate. Features: rerror_rate, srv_rerror_rate. Protocol TCP, top services include private and http. Flags mostly REJ. This looks like rejected connection attempts, maybe brute force attacks.

- **Cluster 4** (231 samples, ~26% anomalies):
Mixed cluster. Features: dst_bytes, hot, logged_in. TCP, service mostly FTP. Could represent occasional abnormal file transfers.

- **Cluster 5** (939 samples, ~89% anomalies):
Features: dst_host_count, srv_diff_host_rate. Protocol mostly ICMP, service eco_i. Likely ICMP-based scanning or ping floods.

- **Cluster 6** (1 sample, 100% anomaly):
Single extreme anomaly. Features include num_root, num_compromised, root_shell. Protocol TCP, service Telnet. This is critical intrusion attempt, very high priority.

- **Cluster 7** (3894 samples, ~28% anomalies):
Mixed cluster. Protocol mostly UDP, services like domain_u. Could be DNS-related traffic, some anomalies, maybe exfiltration attempts or misconfigured queries.

**Where to Focus**

- High-priority anomaly clusters: 0, 3, 5, 6
- 0 → Scanning/probing. Large volume, almost all anomalies.
- 3 → Rejected connection attempts, likely brute force.
- 5 → ICMP-based network attacks, significant anomaly rate.
- 6 → Single critical intrusion attempt, must investigate immediately.

- Medium-priority clusters: 7, 4
- 7 → Some anomalies in DNS/UDP traffic; could be exfiltration or misconfigurations.
- 4 → Occasional abnormal file transfers; investigate for sensitive data movement.

- Low-priority / mostly normal: 1, 2
- 1 → Normal web traffic. Monitor but low risk.
- 2 → Rare normal remote access; no immediate action.

**Why Focus Here**

Clusters 0, 3, 5, 6 are almost entirely anomalous and represent either scanning, brute force, ICMP attacks, or a critical intrusion. Ignoring them could leave the system vulnerable.
- Cluster 7 has mixed anomalies in UDP/DNS; worth monitoring because DNS traffic can hide exfiltration.
- Cluster 1 is mostly normal; focusing here is low ROI.
- Clusters 2 and 4 are small or mixed; lower immediate threat but can be reviewed for context.

You’ve done the hard part — now it’s about translating these technical groupings into operational insight. Let’s keep pushing toward actionable threat segmentation.

— Cheit Geepity
Cybersecurity Strategy Lead


## Deployment

This project is deployed and version-controlled on GitHub. All code, notebooks, dashboard and documentation are available in this repository.

- The Power BI dashboard will be added to the dashboard folder in the project repository for easy access and sharing.
- To use the analysis notebooks, clone the repository and run the Jupyter notebooks locally or in a cloud environment (e.g., Google Colab, VS Code).
- The cleaned data, analysis results, and dashboard files are organized in the respective folders (clean, dashboard).

## Main Data Analysis Libraries

| Library                | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| pandas                 | Data manipulation and analysis; works with DataFrames and CSV files          |
| numpy                  | Numerical computing, arrays, and mathematical functions                      |
| matplotlib             | Plotting and visualization library for static charts                         |
| plotly                 | Interactive plotting and visualization library                               |
| scikit-learn           | Machine learning algorithms and preprocessing (clustering, PCA, metrics)     |
| sklearn.model_selection| Tools for splitting data and cross-validation                                |
| sklearn.preprocessing  | Data preprocessing (scaling, encoding)                                       |
| sklearn.compose        | ColumnTransformer for combining preprocessing steps                          |
| sklearn.cluster        | Clustering algorithms (e.g., KMeans)                                         |
| sklearn.decomposition  | Dimensionality reduction (e.g., PCA)                                         |
| sklearn.ensemble       | Ensemble methods (e.g., RandomForestClassifier)                              |
| sklearn.metrics        | Model evaluation metrics (e.g., accuracy, silhouette score, ARI, purity)     |
| IPython.display        | Displaying rich outputs in Jupyter notebooks                                 |
| collections            | Provides specialized container datatypes (e.g., defaultdict)                 |
| itertools              | Functions for efficient looping and combinatorics                            |

## Credits & Content

* Head image downloaded from [Freepik](https://www.freepik.com/)
* Link to the dataset: [Kaggle](https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection)
* AI (ChatGPT & Copilot)used for code optimisation, ideation, persona generatiuon, markdowns 

## Acknowledgements

Special thanks to **Vasi**, **Code Institute** and all tutors for their invaluable support and guidance throughout this course.
We are proud to have been part of this incredible team, to have participated together in the final hackathon of our program, and to be members of the vibrant Code Institute community. Our collaboration, dedication, and shared passion made this project a truly rewarding and memorable experience.
