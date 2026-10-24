// Runs before every test file: isolated DB + upload dir + fast limits.
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'file:./test.db';
process.env.JWT_SECRET = 'test-secret-do-not-use-in-production-0123456789';
process.env.UPLOAD_DIR = 'storage/test-uploads';
process.env.LOGIN_RATE_LIMIT = '1000';
