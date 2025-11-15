from flask import Flask, render_template, request, send_from_directory
import os, json
from werkzeug.utils import secure_filename
from utils import generate_rsa_keys, hash_document, sign_hash, verify_signature

app = Flask(__name__, template_folder="templates", static_folder="static")

# Folders
BASE_DIR = os.getcwd()
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
KEY_FOLDER = os.path.join(BASE_DIR, "keys")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["KEY_FOLDER"] = KEY_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)


def ensure_keys():
    """Ensure RSA keys exist or generate new ones."""
    private_key = os.path.join(KEY_FOLDER, "private_key.pem")
    public_key = os.path.join(KEY_FOLDER, "public_key.pem")

    if not os.path.exists(private_key) or not os.path.exists(public_key):
        print("Key pair missing → generating new keys...")
        generate_rsa_keys(KEY_FOLDER)
    else:
        print("Keys found → OK")


ensure_keys()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sign", methods=["POST"])
def sign_file():
    try:
        file = request.files["file"]
        algo = request.form.get("algo", "sha256")

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Hash and Sign
        doc_hash = hash_document(file_path, algo)
        signature = sign_hash(doc_hash, KEY_FOLDER)

        sig_file = filename + ".sig.json"
        sig_path = os.path.join(UPLOAD_FOLDER, sig_file)

        with open(sig_path, "w") as f:
            json.dump({
                "filename": filename,
                "hash": doc_hash,
                "signature": signature.hex(),
                "algorithm": algo
            }, f, indent=4)

        return render_template("index.html",
                               message="Document signed successfully!",
                               hash=doc_hash,
                               sig_filename=sig_file)

    except Exception as e:
        return render_template("index.html", message=f"Error: {e}")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "GET":
        return render_template("verify.html")

    try:
        file = request.files["file"]
        sig = request.files["sig"]

        filename = secure_filename(file.filename)
        doc_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(doc_path)

        sig_data = json.load(sig)

        doc_hash = hash_document(doc_path, sig_data["algorithm"])
        signature = bytes.fromhex(sig_data["signature"])

        valid = verify_signature(doc_hash, signature, KEY_FOLDER)

        if valid:
            msg = "✔ Signature is VALID! Document is authentic."
        else:
            msg = "✘ INVALID signature! Document may be modified."

        return render_template("verify.html", message=msg)

    except Exception as e:
        return render_template("verify.html", message=f"Error: {e}")


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == "__main__":
    print("Starting Secure Document Authentication System...")
    app.run(debug=True)
