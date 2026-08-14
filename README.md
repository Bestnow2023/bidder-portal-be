# Bidder Portal API

MongoDB-backed API for the bidder portal frontend.

## Prerequisites

- Node.js `>=22.13.0`
- A MongoDB Atlas or local MongoDB connection string
- A Vercel account/project

## Local Setup

```bash
npm install
cp .env.local.example .env.local
npm run dev
```

Set the backend environment values in `.env.local`:

```text
MONGODB_URI="mongodb+srv://USER:PASSWORD@CLUSTER.mongodb.net/bidder_portal?retryWrites=true&w=majority"
MONGODB_DB="bidder_portal"
PORTAL_MODE="dev"
ALLOWED_ORIGINS="http://localhost:3000"
PORT="4000"
```

The API runs locally at `http://localhost:4000/api/portal`.

## Vercel Setup

1. Create a Vercel project from `Bestnow2023/bidder-portal-be`.
2. Add `MONGODB_URI`, optional `MONGODB_DB`, `PORTAL_MODE`, and
   `ALLOWED_ORIGINS` in Vercel Project Settings -> Environment Variables.
3. Set `ALLOWED_ORIGINS` to your frontend URL, for example
   `https://bidder-portal.vercel.app`.
4. Set `PORTAL_MODE` to `live` for production.
5. Deploy.
6. In the frontend Vercel project, set `NEXT_PUBLIC_API_BASE_URL` to this
   backend URL.

## Modes

- `PORTAL_MODE=dev`: seeds demo accounts and allows demo email sign-in.
- `PORTAL_MODE=live`: disables demo accounts and requires unknown users to sign
  up first. The first real live signup becomes the initial approved admin;
  later signups become pending bidders for admin approval.

## API

- `GET /api/portal?email=admin@portal.local`: load portal data.
- `POST /api/portal`: run portal actions with JSON body:
  `signIn`, `updateUser`, `savePaymentMethod`, `saveWorkLog`, `addPayment`, or
  `addChatMessage`.

The API creates MongoDB indexes automatically on first use and seeds:

- `admin@portal.local`
- `maya.bidder@example.com`
- `pending.bidder@example.com`

## Commands

- `npm run dev`: start the local API server
- `npm start`: start the local API server without watch mode
- `npm test`: run smoke tests
