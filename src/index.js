const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: 'variables.env' });
const createServer = require('./createServer');
const db = require('./db');

const server = createServer();

//cors
//server.express.use(cors('*'));
/* server.express.use(function(req, res, next) {
  res.header('Access-Control-Allow-Origin', [
    'http://localhost:7777',
    /\.localhost$/,
    '*.herokuapp.com/',
    '*.herokuapp.com'
  ]);
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  next();
}); */

server.express.use(function(req, res, next) {
  res.header(
    'Access-Control-Allow-Origin',
    'https://sickfits-next-produ.herokuapp.com'
  );
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  next();
});

//TODO use express middleware to handle cookies JWT
server.express.use(cookieParser());

//decode JWT so we can get the user Id on each request
server.express.use((req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const { userId } = jwt.verify(token, process.env.APP_SECRET);
    //put user id
    req.userId = userId;
  }
  next();
});

// 2_ create a middleware that populates the user on each request
server.express.use(async (req, res, next) => {
  if (!req.userId) return next();
  const user = await db.query.user(
    { where: { id: req.userId } },
    '{id, permissions, email, name}'
  );
  req.user = user;
  console.log(user);
  next();
});

//start it!

server.start(
  {
    cors: {
      credentials: true,
      origin: [
        'http://localhost:7777',
        /\.localhost$/,
        '*.herokuapp.com/',
        '*.herokuapp.com',
        process.env.FRONTED_URL
      ]
    }
  },
  deets => {
    console.log(
      `Server is now running on port http://localhost:${deets.port} `
    );
  }
);
