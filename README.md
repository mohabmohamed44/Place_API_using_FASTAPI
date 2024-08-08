# PLACE API (CAFE or WORKSPACE)

## Description
The Cafe API is an API for managing places, users, and reviews. It allows users to create accounts, login, create and manage places, and leave reviews for places.

## Endpoints

### Users
- `POST /users/`: Create a new user
- `GET /users/me/`: Get the current user's profile
- `PUT /users/me/`: Update the current user's profile

### Authentication
- `POST /token`: Login to get an access token

### Places
- `GET /places/`: Get all places
- `POST /places/`: Create a new place
- `GET /places/{place_id}`: Get a specific place
- `PUT /places/{place_id}`: Update a place
- `DELETE /places/{place_id}`: Delete a place
- `GET /places/search/`: Search for places
- `GET /places/category/`: Get places by category (coffee, wifi, food)
- `GET /places/nearby/`: Get nearby places

### Reviews
- `POST /reviews/`: Create a new review
- `GET /places/{place_id}/reviews/`: Get reviews for a place

### Root
- `GET /`: Root endpoint

## Security
The API uses Bearer authentication for endpoints that require authentication. The access token can be obtained by logging in at the `/token` endpoint.

## Schemas

### `PlaceBase`
- `name`: string
- `description`: string
- `coffee`: boolean
- `wifi`: boolean
- `food`: boolean
- `lat`: float
- `lng`: float

### `PlaceCreate`
- Extends `PlaceBase`

### `PlaceOut`
- Extends `PlaceBase`
- `id`: integer

### `UserCreate`
- `username`: string
- `email`: string
- `password`: string

### `UserOut`
- `id`: integer
- `username`: string
- `email`: string
- `is_active`: boolean

### `Token`
- `access_token`: string
- `token_type`: string

### `DeleteResponse`
- `ok`: boolean

### `ReviewCreate`
- `place_id`: integer
- `rating`: integer
- `comment`: string

### `ReviewOut`
- Extends `ReviewCreate`
- `id`: integer
- `user_id`: integer

## Running the API
The API can be run locally on `http://localhost:8000`.