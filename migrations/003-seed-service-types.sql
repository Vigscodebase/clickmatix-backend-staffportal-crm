-- Up
-- We use INSERT OR IGNORE so that if you run this migration twice, 
-- it won't crash trying to insert duplicates into a UNIQUE column.
INSERT OR IGNORE INTO service_types (name) VALUES 
  ('SEO'), 
  ('G-ADS'), 
  ('META'), 
  ('EMAIL'), 
  ('SMM'), 
  ('Development');

-- Down
-- If we roll back, we remove only the default ones we added.
DELETE FROM service_types WHERE name IN ('SEO', 'G-ADS', 'META', 'EMAIL', 'SMM', 'Development');