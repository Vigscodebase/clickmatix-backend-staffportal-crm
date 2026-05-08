-- Up
ALTER TABLE clients ADD COLUMN team_leader_id INTEGER;

-- Down
ALTER TABLE clients DROP COLUMN team_leader_id;