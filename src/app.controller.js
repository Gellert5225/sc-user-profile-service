module.exports = function(app) {
  app.get('/', (req, res) => {
    res.status(200).send({ status: 'User profile service is healthy' });
  });
}