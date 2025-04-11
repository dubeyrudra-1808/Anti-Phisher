
# 🛡️ Anti-Phisher

A machine learning-based Flask web app to detect phishing URLs in real-time. It helps identify malicious links and protect users from phishing attacks.

## 🚀 Features

- Machine learning model to classify phishing URLs
- Web-based interface using Flask
- Easy to use and extend
- Lightweight and fast

## 📂 Project Structure

```
├── app.py             # Flask web application
├── model_train.py     # Script to train the ML model
├── phishing.pkl       # Serialized trained model
├── requirements.txt   # Required Python packages
└── templates/
    └── index.html     # Frontend HTML template
```

## 🔧 Installation

1. **Clone the repository**

```bash
git clone https://github.com/dubeyrudra-1808/Anti-Phisher.git
cd Anti-Phisher
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Train the model**

```bash
python model_train.py
```

> This will create a `phishing.pkl` model file that the app uses for predictions.

4. **Run the Flask app**

```bash
python app.py
```

5. **Access the app**

Open your browser and go to: [http://localhost:5000](http://localhost:5000)

---

## 📌 Note

- Ensure `phishing.pkl` is present in the same directory as `app.py`.
- You can customize the dataset and model training logic in `model_train.py`.

## 🙌 Author

**Rudra Dubey**  
🔗 [GitHub: dubeyrudra-1808](https://github.com/dubeyrudra-1808)

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
