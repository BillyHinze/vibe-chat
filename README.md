# VIBE Chat 🔥

## Deploy to Railway (3 steps)

### 1. Put files on GitHub
- Go to github.com → sign in → click **+** → **New repository** → name it `vibe-chat` → **Create**
- Upload all these files (drag and drop works on GitHub):
  ```
  server.js
  package.json
  railway.json
  public/
    index.html
  ```

### 2. Deploy on Railway
- Go to railway.app → sign in with GitHub
- **New Project** → **Deploy from GitHub repo** → pick `vibe-chat`
- Go to **Variables** tab → add one variable:
  - `JWT_SECRET` = any random string (e.g. `mychat2025secret`)
- Go to **Settings** → **Networking** → click **Generate Domain**

### 3. Open your app
- Click the domain Railway gave you — that's your live chat!
- Share that link with your friends

## Owner account
Sign up in the app with the username `billy` to get admin powers (👑).
