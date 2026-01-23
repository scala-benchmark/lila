-- Analytics database initialization
CREATE TABLE IF NOT EXISTS player_statistics (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    games_played INTEGER DEFAULT 0,
    wins INTEGER DEFAULT 0,
    losses INTEGER DEFAULT 0,
    rating INTEGER DEFAULT 1500,
    country VARCHAR(100),
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO player_statistics (username, games_played, wins, losses, rating, country) VALUES
('magnus_fan', 1542, 892, 650, 2145, 'Norway'),
('chess_master99', 3201, 1876, 1325, 1987, 'United States'),
('tactical_queen', 876, 512, 364, 1756, 'Russia'),
('endgame_wizard', 2103, 1205, 898, 2034, 'India'),
('blitz_king', 4521, 2654, 1867, 1823, 'Germany');



