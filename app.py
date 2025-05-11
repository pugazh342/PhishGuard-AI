import streamlit as st
import pandas as pd
import joblib
from phish_model import AdvancedPhishingDetector  # Your existing class
import time
import matplotlib.pyplot as plt
import seaborn as sns
from io import StringIO

# Configure page
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main {
        background-color: #f0f2f6;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 10px 24px;
    }
    .stTextInput>div>div>input {
        padding: 10px;
    }
    .header {
        color: #2c3e50;
    }
    .positive {
        color: #e74c3c;
        font-weight: bold;
    }
    .negative {
        color: #2ecc71;
        font-weight: bold;
    }
    .feature-importance {
        background-color: white;
        border-radius: 10px;
        padding: 15px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize detector
@st.cache_resource
def load_detector():
    return AdvancedPhishingDetector()

try:
    saved = joblib.load("advanced_phishing_model.pkl")
    detector.model = saved['model']
    detector.feature_columns = saved['feature_columns']
except:
    st.warning("Model not trained yet. Please train the model first.")


detector = load_detector()

# Sidebar for model management
with st.sidebar:
    st.title("Model Management")
    st.markdown("---")
    
    # Model training section
    st.subheader("Train New Model")
    uploaded_file = st.file_uploader("Upload training dataset (CSV)", type=["csv"])
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            if st.button("Train Model"):
                with st.spinner("Training in progress..."):
                    progress_bar = st.progress(0)
                    
                    # Save to temp file
                    with open("temp_dataset.csv", "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    
                    # Train model (simulating progress)
                    for percent_complete in range(100):
                        time.sleep(0.02)
                        progress_bar.progress(percent_complete + 1)
                    
                    detector.train_model("temp_dataset.csv")
                    st.success("Model trained successfully!")
                    st.balloons()
        except Exception as e:
            st.error(f"Error: {str(e)}")
    
    st.markdown("---")
    st.subheader("Settings")
    threshold = st.slider("Detection Threshold", 0.5, 1.0, 0.85, 0.01)
    detector.threshold = threshold

# Main content
st.title("🛡️ PhishGuard AI")
st.markdown("Advanced phishing URL detection using machine learning")

# Tab interface
tab1, tab2, tab3 = st.tabs(["Single URL Check", "Bulk Analysis", "Model Insights"])

with tab1:
    st.subheader("Check Individual URL")
    url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Analyze URL", disabled=not url_input):
            with st.spinner("Analyzing..."):
                try:
                    prediction, confidence = detector.predict(url_input)
                    
                    st.markdown("### Analysis Results")
                    st.markdown(f"**URL:** `{url_input}`")
                    
                    if prediction == "Phishing":
                        st.markdown(f"**Status:** <span class='positive'>⚠️ PHISHING DETECTED</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"**Status:** <span class='negative'>✅ LEGITIMATE</span>", unsafe_allow_html=True)
                    
                    st.markdown(f"**Confidence:** {confidence:.2%}")
                    
                    # Show gauge
                    fig, ax = plt.subplots(figsize=(6, 1))
                    ax.barh(['Risk'], [confidence], color='#e74c3c' if prediction == "Phishing" else '#2ecc71')
                    ax.set_xlim(0, 1)
                    ax.set_xticks([])
                    ax.text(confidence/2, 0, f"{confidence:.0%}", ha='center', va='center', color='white', fontsize=12)
                    st.pyplot(fig)
                    
                except Exception as e:
                    st.error(f"Analysis failed: {str(e)}")
    
    with col2:
        st.markdown("""
        **Tips for checking URLs:**
        - Look for misspellings in domain names
        - Check for HTTPS (but don't trust it blindly)
        - Be wary of URLs with many special characters
        - Watch for subdomains that mimic legitimate sites
        """)

with tab2:
    st.subheader("Bulk URL Analysis")
    st.markdown("Upload a file containing multiple URLs (one per line or CSV column named 'url')")
    
    uploaded_bulk = st.file_uploader("Choose file", type=["txt", "csv"])
    
    if uploaded_bulk is not None:
        try:
            if uploaded_bulk.name.endswith('.csv'):
                df = pd.read_csv(uploaded_bulk)
                if 'url' not in df.columns:
                    st.warning("CSV should have a column named 'url'")
                else:
                    urls = df['url'].tolist()
            else:
                stringio = StringIO(uploaded_bulk.getvalue().decode("utf-8"))
                urls = [line.strip() for line in stringio if line.strip()]
            
            if st.button("Analyze Bulk URLs"):
                results = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i, url in enumerate(urls):
                    try:
                        prediction, confidence = detector.predict(url)
                        results.append({
                            'URL': url,
                            'Status': prediction,
                            'Confidence': confidence,
                            'Risk': 'High' if prediction == "Phishing" else 'Low'
                        })
                    except:
                        results.append({
                            'URL': url,
                            'Status': 'Error',
                            'Confidence': 0,
                            'Risk': 'Unknown'
                        })
                    
                    progress = (i + 1) / len(urls)
                    progress_bar.progress(progress)
                    status_text.text(f"Processed {i+1}/{len(urls)} URLs")
                
                results_df = pd.DataFrame(results)
                st.success("Analysis complete!")
                
                # Show results
                st.dataframe(results_df.style.applymap(
                    lambda x: 'background-color: #ffcccc' if x == 'Phishing' else '', 
                    subset=['Status']
                ))
                
                # Download button
                csv = results_df.to_csv(index=False)
                st.download_button(
                    label="Download Results",
                    data=csv,
                    file_name='phishing_analysis_results.csv',
                    mime='text/csv'
                )
                
                # Stats
                phishing_count = results_df[results_df['Status'] == 'Phishing'].shape[0]
                st.metric("Phishing URLs Detected", f"{phishing_count}/{len(results_df)}")
                
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")

with tab3:
    st.subheader("Model Performance Insights")
    
    if hasattr(detector, 'model'):
        # Feature importance
        st.markdown("### Feature Importance")
        try:
            feature_importance = pd.DataFrame({
                'Feature': detector.feature_columns,
                'Importance': detector.model.feature_importances_
            }).sort_values('Importance', ascending=False)
            
            fig, ax = plt.subplots(figsize=(10, 6))
            sns.barplot(x='Importance', y='Feature', data=feature_importance.head(15), ax=ax)
            ax.set_title("Top 15 Important Features")
            st.pyplot(fig)
            
            # Show full table
            with st.expander("Show Complete Feature Importance"):
                st.dataframe(feature_importance)
        except:
            st.warning("Feature importance data not available")
        
        # Model metrics
        st.markdown("### Model Metrics")
        col1, col2, col3 = st.columns(3)
        col1.metric("Detection Threshold", f"{detector.threshold:.0%}")
        col2.metric("Model Type", "Gradient Boosting")
        if detector.feature_columns:
         col3.metric("Feature Count", len(detector.feature_columns))
        else:
         col3.metric("Feature Count", "Not Available")

    else:
        st.warning("No trained model available. Please train a model first.")

# Footer
st.markdown("---")
st.markdown("""
**About PhishGuard AI:**
This tool uses advanced machine learning to detect phishing URLs based on multiple features including:
- URL structure analysis
- Domain characteristics
- Content-based features
- Threat intelligence
""")