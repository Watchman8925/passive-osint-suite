# OSINT Suite - Quick Start Guide

## ⚡ 5-Minute Setup

### Step 1: Generate Secret Key

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output.

### Step 2: Configure .env

```bash
# Open .env file and replace this line:
OSINT_SECRET_KEY=CHANGE_THIS_TO_SECURE_RANDOM_VALUE_MINIMUM_32_CHARS

# With your generated key:
OSINT_SECRET_KEY=<paste-your-key-here>
```

Also set these required passwords:

```bash
POSTGRES_PASSWORD=your_secure_db_password
GRAFANA_PASSWORD=your_secure_grafana_password
```

### Step 3: Install Dependencies

```bash
# Backend
pip install -r requirements.txt

# Frontend
cd web
npm install
cd ..
```

### Step 4: Start Services

```bash
# Start Docker services (Redis, PostgreSQL, etc.)
docker-compose up -d

# Start backend API
python api/api_server.py &

# Start frontend (in another terminal)
cd web && npm run dev
```

### Step 5: Verify

Open in your browser:
- Frontend: http://localhost:3000
- API Health: http://localhost:8000/api/health
- API Docs: http://localhost:8000/docs

---

## 🎉 You're Ready!

The OSINT Suite is now running with:

✅ Secure secret management
✅ Input validation
✅ Rate limiting
✅ Error boundaries
✅ Health checks
✅ Async file I/O

---

## 📚 Next Steps

1. **Read the Security Guide**: [SECURITY_GUIDE.md](SECURITY_GUIDE.md)
2. **Production Deployment**: [SETUP_GUIDE.md](SETUP_GUIDE.md)
3. **Review Changes**: [CODE_REVIEW_SUMMARY.md](CODE_REVIEW_SUMMARY.md)

---

## ⚠️ Important Notes

### Development Mode
- Dev authentication is **disabled** by default
- To enable: Set `ENABLE_DEV_AUTH=1` in `.env` (development only!)
- **NEVER** enable dev auth in production

### Environment Configuration
- `ENVIRONMENT=development` by default
- Change to `ENVIRONMENT=production` for production deployments

### CORS Origins
- Default: `http://localhost:3000,http://localhost:8000`
- Update `CORS_ORIGINS` in `.env` for production domains

---

## 🐛 Troubleshooting

### "OSINT_SECRET_KEY or SECRET_KEY must be set" error
- Make sure you've set either `OSINT_SECRET_KEY` or `SECRET_KEY` in your `.env` file
- Ensure it's not the default placeholder value
- Both variable names are accepted (OSINT_SECRET_KEY is preferred)

### Can't connect to Redis/PostgreSQL
```bash
# Check Docker services are running
docker-compose ps

# Restart if needed
docker-compose restart
```

### Frontend shows "API Offline"
- Make sure backend is running: `python api/api_server.py`
- Check `VITE_API_URL` in `web/.env` file

---

## 🔧 Common Commands

```bash
# Stop all services
docker-compose down

# View logs
docker-compose logs -f

# Restart API
pkill -f api_server.py && python api/api_server.py &

# Rebuild frontend
cd web && npm run build

# Check health
curl http://localhost:8000/api/health/detailed
```

---

## 📞 Need Help?

- **Detailed Setup**: See [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Security Info**: See [SECURITY_GUIDE.md](SECURITY_GUIDE.md)
- **Review Summary**: See [CODE_REVIEW_SUMMARY.md](CODE_REVIEW_SUMMARY.md)

---

**Version:** 2.0.0
**Last Updated:** 2025-10-03
