# Campus Canteen Backend

## Deployment Instructions

### 1. MongoDB Atlas Setup
1. Go to https://www.mongodb.com/cloud/atlas
2. Create free account
3. Create a cluster
4. Get connection string

### 2. Deploy to Render
1. Push code to GitHub
2. Go to https://render.com
3. Connect GitHub repository
4. Add environment variables
5. Deploy!

### Environment Variables Required:
- `MONGODB_URI` - Your MongoDB Atlas connection string
- `JWT_SECRET` - Random secret key for JWT
- `EMAIL_USER` - Gmail address for sending OTPs
- `EMAIL_PASS` - Gmail app password
- `PORT` - Will be set by Render automatically

## Local Development
```bash
npm install
npm start
```
