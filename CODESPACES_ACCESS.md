# Codespaces Port Access Guide

## Current Status
✅ Backend running on port 8000
✅ Frontend running on port 3000

## How to Access the Application

### Method 1: Use VS Code Ports Tab (Recommended)
1. Click on the **PORTS** tab in the bottom panel of VS Code
2. You should see ports 3000 and 8000 listed
3. For port 3000:
   - Right-click on the port
   - Select **"Port Visibility"** → **"Public"**
   - Click the globe icon 🌐 or the URL to open in browser
4. This should open the frontend application in a new tab

### Method 2: Manual URL Construction
Your Codespace name: `vigilant-space-goldfish-jjwv6q66jvxxcp499`

Frontend URL should be:
```
https://vigilant-space-goldfish-jjwv6q66jvxxcp499-3000.app.github.dev
```

Backend URL should be:
```
https://vigilant-space-goldfish-jjwv6q66jvxxcp499-8000.app.github.dev
```

### Method 3: Port Forwarding Settings
If the above doesn't work, you may need to:
1. Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
2. Type "Ports: Focus on Ports View"
3. Right-click port 3000 → "Port Visibility" → "Public"
4. Try opening the forwarded URL again

## Troubleshooting

### If you still get redirected back:
1. **Check port visibility**: Ensure port 3000 is set to "Public" not "Private"
2. **Check browser**: Try opening in an incognito/private window
3. **Check authentication**: Make sure you're logged into GitHub in the browser
4. **Clear cookies**: The redirect might be cached

### Test the backend directly:
Visit the backend health endpoint:
```
https://vigilant-space-goldfish-jjwv6q66jvxxcp499-8000.app.github.dev/api/health
```

This should return JSON with status information.

## Expected Result
Once working, you should see:
- Dark gradient background
- Glass morphism UI cards
- Navigation tabs (Dashboard, Search, AI Assistant, etc.)
- Proper spacing and typography
- The application should NOT redirect you back to the editor
