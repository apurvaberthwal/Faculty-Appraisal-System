import { config } from 'dotenv';
import ejs from 'ejs'; // Templating engine
import jwt from 'jsonwebtoken';
import { createTransport } from 'nodemailer'; // For sending emails
import puppeteer from 'puppeteer'; // For browser automation
import facultyDb from './faculty.db.js';

config();
export const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.render("./superAdmin/login",{error :"Login As SuperAdmin Before Continuing."});
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(500).send({ error: 'Failed to authenticate token.' });
    }

    // Check if the user is a SuperAdmin
    if (decoded.username !== 'ADMIN') {
      return res.render("error", {error: "Access denied. Not authorized."});
  }

    // If everything is good, save the decoded token to the request for use in other routes
    req.user = decoded;
    next();
  });
};

export const transporter = createTransport({
 
  // Use Gmail service for sending emails
 service: 'gmail',
 auth: {
   user: process.env.SMTP_MAIL, // SMTP email
   pass: process.env.SMTP_PASS  // SMTP password
 }
});

export function generateOrderID() {
  // Generate a random 4-digit integer
  const randomInt = Math.floor(1000 + Math.random() * 9000); // 1000 to 9999

  // Concatenate with the prefix
  const orderID = "ORD" + randomInt;

  return orderID;
}

export function generateTransactionId() {
  // Get current date and time
  const now = new Date();

  // Extract date components
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0'); // Month is zero-based
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');

  // Generate random integer between 1000 and 9999
  const randomInt = Math.floor(Math.random() * 9000) + 1000;

  // Construct transaction ID using date and random integer
  const transactionId = `${year}${month}${day}${hours}${minutes}${seconds}${randomInt}`;

  return transactionId;
}


export async function sendEmailAndRenderTemplate(result, res) {
  try {
    // Format the date of birth (DOB) to a user-friendly format
    const dob = new Date(result[0].dob);
    const formattedDOB = dob.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit'
    });

    // Update the result with the formatted DOB
    result[0].dob = formattedDOB;

    // Render the EJS template
    const html = ejs.render(EJSTemplate, { userData: result[0] });

    // Launch Puppeteer and generate the PDF
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.setContent(html);
    const pdfBuffer = await page.pdf();
    await browser.close();

    // Send email with attachment
    const mailOptions = {
      from: process.env.SMTP_MAIL,
      to: result[0].email_id,
      subject: 'Acknowledgment of Course Application from Fergusson College',
      text: 'Thank you for acknowledging your application for courses at Fergusson College. We appreciate your interest in our institution and look forward to reviewing your application.Please find attached your application details.',
      attachments: [{ filename: 'application_details.pdf', content: pdfBuffer }]
    };

    await transporter.sendMail(mailOptions);

    
    setTimeout(() => {
      // Render the EJS template with the updated data
      res.render('./SuperAdmin/show_applicants.ejs', { applicants: result, showAlert: true });
    }, 3000); 
    return true; // Indicate that email was sent successfully
  } catch (error) {
    console.error('Error sending email:', error);
    return false; // Indicate that email sending failed
  }
}

import { v2 as cloudinary } from "cloudinary";

import fs from "fs";
config({path: "../../.env"});



cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "dqzblredc", 
    api_key: process.env.CLOUDINARY_CLOUD_API_KEY ||  "599838769976382",
    api_secret: process.env.CLOUDINARY_CLOUD_API_SECRET || "oqL_0Ji4KbHw3Ap65l5DcmdUo4k"
  });
 

export const uploadToCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null
        //upload the file on cloudinary
        console.log("local",localFilePath)
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        // file has been uploaded successfull
        console.log("file is uploaded on cloudinary ", response.url);
        fs.unlinkSync(localFilePath)
        return response;

    } catch (error) {
        console.log("error uploading",error)
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed
        return null;
    }
}





export const jwtMiddleware = (req, res, next) => {
  if (req.cookies.token) {
      try {
          const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
          req.user = user;
          console.log('Decoded JWT:', user);
          console.log('User ID:', user.user_id);
          console.log('Role:', user.role); // Log user role
          res.locals.loggedIn = true;
          res.locals.role = user.role; // Set role in locals
      } catch (err) {
          console.error('JWT verification error:', err);
          res.clearCookie('token');
          res.locals.loggedIn = false;
      }
  } else {
      res.locals.loggedIn = false;
  }
  next();
};

export const authorizeRole = (roles) => {
  return (req, res, next) => {
      if (req.user && roles.includes(req.user.role)) {
          next();
      } else {
          res.render("error")
      }
  };
};



export const sendApprovalEmail = async (user) => {
  const mailOptions = {
      from: process.env.SMTP_MAIL,
      to: user.email_id,
      subject: 'Your Account Has Been Approved',
      text: `Dear ${user.first_name} ${user.last_name},\n\nYour account has been approved. Here are your login credentials:\n\nUsername: ${user.email_id}\nPassword:"Misfits"\n\nBest regards,\nYour Institution`
  };

  try {
      await transporter.sendMail(mailOptions);
  } catch (error) {
      console.error('Error sending email:', error);
  }
};

export async function sendCommitteeEmails(members) {
  try {
      for (const member of members) {
          const mailOptions = {
              from: process.env.SMTP_MAIL,
              to: member.email_id,
              subject: 'Committee Membership Notification',
              text: `Dear ${member.first_name} ${member.last_name},

              Congratulations! You have been selected as a committee member.

              Institute: ${member.institution_name}
              Department: ${member.department_name}
              Start Date: ${new Date(member.start_date).toLocaleDateString()}
              End Date: ${new Date(member.end_date).toLocaleDateString()}
              Best Regards,
              Your Institute`
          };

          await transporter.sendMail(mailOptions);
      }
      console.log('Emails sent successfully');
  } catch (error) {
      console.error('Error sending emails:', error);
  }
}
export async function getParametersByCriteriaId(criteriaId) {
  const query = 'SELECT parameter_description, parameter_max_marks FROM parameters WHERE criteria_id = ?';
  const [results] = await facultyDb.query(query, [criteriaId]);
  return results;
}
export async function getCriteriaWithParameters(selectedCriteriaIds) {
  const query = `
      SELECT c.criteria_id, c.criteria_description, p.c_parameter_id, p.parameter_description, p.parameter_max_marks
      FROM criteria_master c
      LEFT JOIN c_parameter_master p ON c.criteria_id = p.criteria_id
      WHERE c.criteria_id IN (?)
  `;
  
  const results = await facultyDb.query(query, [selectedCriteriaIds]);
  
  // Access only the first part of the results, which contains the data
  const dataRows = results[0]; // Assuming the first element is the actual data
  console.log("Raw query results:", dataRows); // Log the raw results

  // Check if dataRows is an array and contains data
  if (!Array.isArray(dataRows) || dataRows.length === 0) {
    console.error("No results found for the query");
    return [];
  }

  const criteria = dataRows.reduce((acc, row) => {
      const criterionId = row.criteria_id; // Get the criteria_id from the row
      
      // Check if the criterionId is valid
      if (!criterionId) {
          console.warn("Encountered row with undefined criteria_id", row);
          return acc; // Skip this iteration
      }
      
      // Initialize the criterion if it doesn't exist
      if (!acc[criterionId]) {
          acc[criterionId] = {
              criteria_id: criterionId,
              criteria_description: row.criteria_description,
              parameters: []
          };
      }

      // Only add parameters if c_parameter_id exists
      if (row.c_parameter_id) {
          acc[criterionId].parameters.push({
              c_parameter_id: row.c_parameter_id,
              parameter_description: row.parameter_description,
              parameter_max_marks: row.parameter_max_marks
          });
      }

      return acc;
  }, {});

  console.log("Criteria object before return:", criteria); // Log the processed criteria
  return Object.values(criteria);
}
export async function getCriteriaAppliedPercentage(userId, appraisalId) {
    try {
        const [result] = await facultyDb.query(`
            SELECT
                total_criteria.total AS total_criteria,
                COUNT(DISTINCT cp.criteria_id) AS criteria_applied
            FROM
                self_appraisal_score_master sasm
            LEFT JOIN
                c_parameter_master cp ON sasm.c_parameter_id = cp.c_parameter_id
            LEFT JOIN (
                SELECT
                    appraisal_id,
                    COUNT(DISTINCT criteria_id) AS total
                FROM
                    apprisal_criteria_parameter_master
                WHERE
                    appraisal_id = ?
                GROUP BY
                    appraisal_id
            ) total_criteria ON sasm.appraisal_id = total_criteria.appraisal_id
            WHERE
                sasm.user_id = ? AND sasm.appraisal_id = ? 
            GROUP BY
                total_criteria.total;  -- Add GROUP BY here
        `, [appraisalId, userId, appraisalId]);

        const totalCriteria = result[0]?.total_criteria || 0;
        const criteriaApplied = result[0]?.criteria_applied || 0;

        // Calculate the percentage of criteria applied
        const percentage = totalCriteria > 0 ? (criteriaApplied / totalCriteria) * 100 : 0;

        return { percentage };
    } catch (error) {
        console.error('Error fetching criteria percentage:', error);
        throw error; // Rethrow the error to handle it in the calling function
    }
}
