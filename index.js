import bodyParser from 'body-parser';
import flash from "connect-flash"; // For displaying flash messages
import cookieParser from "cookie-parser";
import cors from "cors";
import { config } from 'dotenv'; //environment variable
import express from 'express'; // Web framework
import session from "express-session";

import CommitteeRoute from "./Routes/Committee.Route.js";
import FacultyRoutes from "./Routes/Faculty.Route.js";
import PrincipalRoute from "./Routes/Principal.Route.js";
import SuperAdminRoute from "./Routes/SuperAdmin.Route.js";
import facultyDb from './faculty.db.js';
config();
const app = express();
app.use(cors());
app.use(cookieParser())
// Define the port number
const PORT = 8800

app.use(express.static('public'));
app.use(express.static('uploads'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Set the view engine to use EJS
app.set('view engine', 'ejs');
app.set('views', './views');
// Set up session middleware
app.use(session({
  secret: 'PixelPioneers',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 week in milliseconds
}));
app.use(flash());

// Error-handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: {
            message: err.message,
            stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack,
        },
    });
});


app.use("/principal",PrincipalRoute);
app.use("/faculty",FacultyRoutes);
app.use("/committee",CommitteeRoute);
app.use("/superAdmin",SuperAdminRoute);

app.get("/", async function (req, res) {
  

  res.render("index.ejs");
});
app.get('/api/departments', async (req, res) => {
  const { institution_id } = req.query;
  try {
      const [departments] = await facultyDb.query(
          'SELECT dept_id, department_name FROM department_master WHERE institution_id = ? AND status = "active"',
          [institution_id]
      );
      res.json(departments);
  } catch (error) {
      console.error('Error fetching departments:', error);
      res.status(500).send('Internal Server Error');
  }
});
app.get('/api/institutes', async (req, res) => {
  try {
      const [institutes] = await facultyDb.query('SELECT institution_id, institution_name FROM institution_master WHERE status = "active"');
      res.json(institutes);
  } catch (error) {
      console.error('Error fetching institutes:', error);
      res.status(500).send('Internal Server Error');
  }
});


// Endpoint for checking the user status
app.get("/check-status", async (req, res) => {
  const email = req.query.email; // Get the email from query parameters
 
  if (!email) {
      return res.status(400).send('Email is required to check the approval status.');
  }

  try {
      // Fetch the user's status from the database using email
      const [result] = await facultyDb.query(
          'SELECT status FROM user_type_master WHERE user_name = ?',
          [email]
      );

      if (result.length > 0) {
          const status = result[0].status;

          // Check if the status is now active
          if (status === 'active') {
              // Send a success response with the approval message
              console.log("pass")
              return res.json({message:'Your request has been approved. Please log in.',username : email});
          } else {
              // If still inactive, send a response with the status
              return res.json({message: 'Your request is still pending.', status: 'inactive'});
          }
      } else {
          return res.status(404).send('User not found.');
      }
  } catch (error) {
      console.error('Error checking user status:', error);
      return res.status(500).send('Internal Server Error');
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
