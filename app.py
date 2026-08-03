from flask import Flask, render_template, request, jsonify # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from datetime import datetime
from hybrid_model import hybrid_predict_phishing # type: ignore

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Optional MySQL connection for production (fallback to SQLite if it fails)īī
MYSQL_URI = "mysql+mysqlconnector://xxxx:@localhost:xxxx/xxxxx"

db = SQLAlchemy(app)



class PhishingResults(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    prediction = db.Column(db.String(20), nullable=False)
    final_score = db.Column(db.Integer)
    heuristic_score = db.Column(db.Integer)
    ml_score = db.Column(db.Float)
    description = db.Column(db.Text)
    risk_level = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Database Initialization
with app.app_context():
    try:
        # Try SQLite first (default)
        db.create_all()
        print("Database initialized (SQLite).")
    except Exception as e:
        print(f"Error initializing SQLite: {e}")

@app.route("/")
def logo():
    return render_template("logo.html")

@app.route("/recent-urls")
def recent_urls():
    try:
        rows = (
            db.session.query(PhishingResults.url, PhishingResults.prediction)
            .order_by(PhishingResults.id.desc())
            .all()
        )
        seen = set()
        results = []
        for url, pred in rows:
            if url not in seen:
                seen.add(url)
                results.append({"url": url, "prediction": pred})
            if len(results) == 8:
                break
        return jsonify(results)
    except Exception:
        return jsonify([])

@app.route("/home", methods=["GET", "POST"])
def index():
    result = None
    error = None
    
    if request.method == "POST":
        url = request.form.get("url")
        lang = request.form.get("lang", "en")
        
        if not url:
            error = "Please provide a valid URL signal."
        else:
            try:
                # Prediction logic
                prediction, score, warning, description, heur, ml, level = hybrid_predict_phishing(url, lang)
                
                result = {
                    "url": url,
                    "prediction": prediction,
                    "score": score,
                    "warning": warning,
                    "description": description,
                    "ml": f"{float(ml):.2f}",
                    "level": level
                }
                
                # Persistence
                new_entry = PhishingResults(
                    url=url,
                    prediction=prediction,
                    final_score=score,
                    heuristic_score=heur,
                    ml_score=ml,
                    description=description,
                    risk_level=level
                )
                db.session.add(new_entry)
                db.session.commit()
                
            except Exception as e:
                import traceback
                print(f"Error during prediction: {e}")
                traceback.print_exc()
                error = f"Logic override: {str(e)}"
    
    return render_template("index.html", result=result, error=error)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
