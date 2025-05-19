const { connect } = require('mongoose');

const mongoConnection = async () => {
  try {
    await connect(process.env.MONGO_URI);
  } catch (error) {
    console.error('MongoDB Connection Error:', error);
    process.exit(1);
  }
};

module.exports = { mongoConnection };
