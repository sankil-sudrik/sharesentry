#!/bin/bash
# Build script for Netlify deployment
set -e

echo "🔨 Building ShareSentry for Netlify..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create data directory if it doesn't exist
mkdir -p data

# Verify Streamlit can start
echo "✅ Verifying Streamlit configuration..."
python -c "import streamlit; print(f'Streamlit {streamlit.__version__} OK')"

# Verify all imports work
echo "✅ Verifying application imports..."
python -c "
from sharesentry.ai import AIError, list_models
from sharesentry.audit import csv_column_summary, run_audit, verify_redaction
from sharesentry.config import Settings, load_settings
from sharesentry.models import Context, Rule, Severity, Status
from sharesentry.parsers import SUPPORTED, parse_document
from sharesentry.redaction import redact_document
from sharesentry.report import DISCLAIMER, report_json, report_markdown
from sharesentry.sample import SAMPLE_RULES, load_sample
from sharesentry.skills import SKILLS, SKILLS_BY_NAME
from sharesentry.store import AuthError, Workspace
print('All imports OK')
"

echo "✅ Build complete! Ready for Netlify deployment."
echo ""
echo "To deploy to Netlify:"
echo "  1. Push this repo to GitHub"
echo "  2. Connect to Netlify"
echo "  3. Build command: pip install -r requirements.txt"
echo "  4. Publish directory: . (root)"
echo "  5. Add environment variables in Netlify dashboard:"
echo "     - AI_PROVIDER (nvidia|nebius|groq|custom)"
echo "     - AI_API_KEY (your API key)"
echo "     - AI_BASE_URL (optional)"
echo "     - AI_MODEL (optional)"
echo "     - SHARESENTRY_DATA_DIR (optional, default ./data)"
echo "     - SHARESENTRY_MAX_UPLOAD_MB (optional, default 10)"