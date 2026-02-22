# Atmos

**Visualize room transformations before you make them.**

Atmos lets you upload a photo of any room and describe how you want it transformed—a gaming setup, birthday party, home office, or whatever you imagine. Get an AI-generated image of your space reimagined, so you can see the result before you lift a finger.

## Features

- Upload a room photo and describe your vision
- AI-powered image transformation (Flux img2img via Replicate)
- Works with any prompt: parties, gaming rooms, offices, reading nooks, and more
- Sign in with Google or email/password
- Clean, branded interface

## Tech Stack

- **Backend:** Flask, Flask-Login, SQLAlchemy
- **Auth:** Supabase (Google OAuth + email/password)
- **Image Generation:** Replicate (Flux img2img)
- **Frontend:** HTML, CSS, Jinja2 templates

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/atmos.git
cd atmos/ProjectFiles
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment variables

Create a `.env` file or set these in your shell:

| Variable | Description |
|----------|-------------|
| `REPLICATE_API_TOKEN` | Your Replicate API key. Get one at [replicate.com/account/api-tokens](https://replicate.com/account/api-tokens) |
| `SECRET_KEY` | Flask session secret (optional; defaults to a dev value) |

**PowerShell (Windows):**

```powershell
$env:REPLICATE_API_TOKEN = "r8_your_token_here"
```

**Bash:**

```bash
export REPLICATE_API_TOKEN="r8_your_token_here"
```

### 5. Run the app

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Replicate Credits

Image generation uses Replicate credits (~$0.012 per image). Add credits at [replicate.com/account/billing](https://replicate.com/account/billing). With less than $5 in credit, rate limits apply (about 1 request per 10 seconds).

## Project Structure

```
ProjectFiles/
├── app.py              # Flask app, routes, Replicate integration
├── requirements.txt
├── templates/          # Login, signup, upload, auth callback
├── static/
│   ├── styles.css
│   ├── app.js
│   └── brand/          # Logo assets
├── static/uploads/     # User-uploaded room photos
└── static/generated/   # AI-generated transformed images
```

## License

MIT
