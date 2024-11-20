***Inspiration*** 💡
Phishing attacks are a persistent and growing threat in the digital world, targeting unsuspecting users by masquerading as legitimate entities to steal sensitive data. Despite various detection mechanisms, cybercriminals continue to innovate, necessitating a robust and adaptive approach to counter these attacks.

**Key Insights**:
Over 48% of emails sent in 2022 were spam, with an estimated 3.4 billion spam emails sent daily.
Phishing attacks resulted in $44.2 million in losses globally in 2021, with each attack costing victims an average of $136.
PhishAlyzer aims to combat these issues by leveraging advanced machine learning algorithms for accurate phishing website detection.

**Problem Statement** 🛡️
Phishing websites significantly threaten user safety, undermining their trust and security in online interactions. Existing detection systems often struggle to keep pace with rapidly evolving phishing tactics, highlighting the need for:

Enhanced feature engineering to identify phishing characteristics effectively.
Deployment of advanced machine learning models to achieve accurate classification.
A user-friendly platform to empower users in staying secure online.
PhishAlyzer addresses these challenges with a state-of-the-art detection system.

**Introduction** 📖
PhishAlyzer is a machine learning-powered app designed to identify and mitigate phishing threats. The app uses an extensive dataset of phishing and legitimate URLs, extracting critical features to train robust models capable of distinguishing between safe and malicious websites.

**Objectives**:

Develop a safer online ecosystem.
Protect sensitive user information.
Enhance trust in digital interactions.
Approach 🧠

1. Data Collection

Phishing URLs: Sourced from PhishTank, containing updated phishing websites.
Legitimate URLs: Acquired from the University of New Brunswick dataset.

2. Feature Extraction
Extracted features are categorised into:

Address Bar Features: Characteristics from the browser's address bar.
Domain-Based Features: Properties of the domain used.
HTML & JavaScript Features: Attributes embedded in the webpage's code.

3. Model Training

Dataset split into 80% training and 20% testing.
Machine learning models implemented:
Decision Tree
Random Forest
XGBoost
Autoencoder Neural Networks
Support Vector Machines
Best Model: XGBoost with 86.7% accuracy.

4. Model Deployment

Model is saved for deployment using Python pickle.
Procedure 🛠️
Install Dependencies
TensorFlow, NumPy, Pandas, scikit-learn
Understand the Dataset
Analyse phishing and legitimate URL characteristics.
Feature Engineering
Extract 17 unique features from URLs.
Train and Save the Model
Evaluate models and select the best-performing algorithm.
Deploy the App
Build a user-friendly interface using Streamlit.

**Results** 📊
After testing multiple algorithms, XGBoost emerged as the most effective model:

Training Accuracy: 86.7%
Testing Accuracy: 85.8%
Learning Outcomes 🎓
Proficiency in implementing machine learning algorithms for classification tasks.
Enhanced understanding of phishing tactics and URL features.
Hands-on experience in feature engineering and data preprocessing.
Development of a deployable app using Streamlit.
Effective team collaboration and project management.
Deployment 🚀
PhishAlyzer is deployed as a web application using Streamlit, providing users with:

Real-time phishing detection.
A simple and intuitive user interface.
Cross-platform accessibility.