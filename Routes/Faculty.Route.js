import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import express from 'express';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import facultyDb from '../faculty.db.js';
import { transporter } from '../service.js';

const router = express.Router();
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userId = req.user.user_id;
        const uploadPath = path.join('public/uploads', userId);

        // Create the directory if it doesn't exist
        fs.mkdirSync(uploadPath, { recursive: true });

        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const userId = req.user.user_id;
       
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = path.extname(file.originalname);
        const filename = `${userId}-${uniqueSuffix}${fileExtension}`;

        // Store the file path in the database without the 'public/' part
        const filePathForDatabase = path.join('uploads', userId, filename);
        req.body.supportive_doc = filePathForDatabase;

        cb(null, filename);
    }
});


const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 1024 * 1024 * 50 // 50MB
    }
});

router.use((req, res, next) => {
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            req.user = user;
            console.log('Decoded JWT:', user); // Log the decoded JWT payload
            console.log('User ID:', user.user_id); // Log the user ID specifically
            res.locals.loggedIn = user.loggedIn;
            res.locals.user = user; // Set a local variable
        } catch (err) {
            console.error('JWT verification error:', err);
            res.clearCookie('token');
            res.locals.loggedIn = false; // Set a local variable
        }
    } else {
        res.locals.loggedIn = false; // Set a local variable
    }
    next();
});



router.get('/login', (req, res) => {
    const message = req.query.message || '';
    const error = req.query.error || '';
    const username = req.query.username || '';
    res.render('./Faculty/login', { message, error, username });
});

router.post('/verify', async function (req, res) {
    const username = req.body.username;
    const otp = req.body.otp;
    console.log('Username:', username);
    console.log('OTP:', otp);
    try {
        const q = await facultyDb.query(`SELECT otp, timestamp FROM otp_master WHERE email_id = ?
        AND status = 'active' ORDER BY timestamp DESC LIMIT 1;`, [username]
        )
        console.log(q);
        const otpData = q[0][0n];
        const oldOTP= otpData.otp;
        const timestamp = otpData.timestamp;
    
        console.log(oldOTP, timestamp);
        const currentTime = new Date().getTime();
        if (currentTime - timestamp > 300000) {
            console.log('The OTP has expired. Please request a new OTP.')
            return res.render('./committee/login', { error: 'The OTP has expired. Please request a new OTP.' });
        }
        if (String(oldOTP) !== String(otp)) {
            console.log('error', 'Invalid OTP.');
            return res.render('./committee/verify', { error: 'Invalid OTP.', username });
        }
        else {
            console.log('success', 'OTP verified successfully.');
            const [result] = await facultyDb.query(
                'UPDATE otp_master SET status = "inactive" WHERE email_id = ? AND otp = ?',
                [username, otp]
            );
            const userSql = await facultyDb.query(
                'SELECT * FROM user_type_master WHERE user_name = ? AND user_type_type= "committee"', [username]);
            const user =userSql [0];
            const sql = "SELECT institution_id FROM user_master WHERE user_type_id = ?";
            const [results] = await facultyDb.query(sql, [user[0].user_type_id]);
            console.log(results);
            const user_id = user[0].user_type_id;
            const role = user[0].user_type_type; // Assuming `user_type_type` indicates role
            const institution_id = results[0].institution_id; // Assuming the query returns at least one result
        
            console.log('User ID from DB:', user_id);
            console.log('Role from DB:', role);
            console.log('Institution ID from DB:', institution_id);
        
            const token = jwt.sign({ user_id, role, institution_id }, process.env.JWT_SECRET, { expiresIn: '2h' });
            console.log('Generated JWT:', token);
            
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/faculty/criteria-status');
        }
    } catch (error) {
        console.error(error);
    }
})


router.post('/login', async (req, res) => {
    console.log("Faculty Login Attempt");

    const username = req.body.uname;
    const email = username;  // Using username as email
    const password = req.body.password;
    console.log("Email/Username: " + email);

    try {
        // Query the database for the user
        const result = await facultyDb.query(
            'SELECT * FROM user_type_master WHERE user_name = ? AND (user_type_type = "employee" OR user_type_type = "committee")',
            [username]
        );

        const user = result[0];
        console.log('User from DB:', user);
        // Check if user exists
        if (!user || user.length === 0) {
            console.log("User does not exist");
            return res.render('./Faculty/login', { error: 'User does not exist', message: '', username: '' });
        }
        
        const user_id = user[0].user_type_id;
        const role = user[0].user_type_type;  
        const status = user[0].status;  
        console.log(role)
        const hashedPassword = user[0].password;  
        // Check if the user status is inactive
        if (status === 'inactive') {
            console.log("User is inactive, redirecting to waiting page");
            return res.redirect(`/faculty/wait?email=${encodeURIComponent(email)}`);
        }

        // Verify password
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        if (!passwordMatch) {
            console.log("Password mismatch");
            return res.render('./Faculty/login', { error: 'Invalid password', message: '', username: email });
        }

        // Check if the password is the default password
        const isDefaultPassword = await bcrypt.compare('Misfits', hashedPassword);
        if (isDefaultPassword) {
            console.log("Default password detected, redirecting to reset password");
            return res.redirect(`/faculty/reset-password?user_id=${username}`);
        }
        if(role === 'committee'){ 
            console.log("Generating")
            const otp = crypto.randomInt(100000, 999999).toString();

            // Store OTP in OTP_MASTER table
            await facultyDb.query(
                'INSERT INTO OTP_MASTER (OTP_ID, EMAIL_ID, OTP, STATUS) VALUES (?, ?, ?, "active")',
                [crypto.randomBytes(16).toString('hex'), username, otp]
            );

            // Send OTP to user's email
            let mailOptions = {
                from: process.env.SMTP_MAIL,
                to: username, // assuming username is the user's email
                subject: '2FA for Committee Member  Login  ',
                text: `Your OTP is ${otp}`
            };

            transporter.sendMail(mailOptions, function(error, info){
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                }
            });
           res.render("./committee/verify",{username:username})
        }
        else{
    

        // If everything is valid, sign and set JWT token
        const token = jwt.sign({ user_id, role }, process.env.JWT_SECRET, { expiresIn: '2h' });
        res.cookie('token', token, { httpOnly: true });

        console.log("Login successful, redirecting to Faculty home");
        return res.redirect('/Faculty/criteria-status');}

    } catch (err) {
        console.error("Server error during login: ", err);
        return res.status(500).send('Server error');
    }
});







router.get('/logout', (req, res) => {
    // Clear the JWT token cookie
    res.clearCookie('token');
    
    // Redirect the user to the login page or home page after logout
    res.redirect('/faculty/login'); // Adjust the path as needed
});



router.get("/home", async (req, res) => {
    console.log('Faculty home');
    const userId = req.user.user_id;
  
    // Pass the user object to the template
    res.render('./Faculty/home');
});



router.get('/register', (req, res) => {

    res.render('./Faculty/registration',{successMsg:"",errorMsg:""});
})
router.post('/register', async (req, res) => {
    const {
        firstName,
        middleName = '', 
        lastName,
        email,
        contact,
        dob,
        panCard,
        aadhaar,
        employeeId,
        instituteId, 
        departmentId 
    } = req.body;
    
    try {
        const password = "Misfits";
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // Insert into user_type_master table
        const sql = `INSERT INTO user_type_master (user_name, password, user_type_type, status) VALUES (?, ?, ?, ?)`;
        try {
            const [result1] = await facultyDb.execute(sql, [email, hashedPassword, 'employee', 'inactive']);
            console.log('Insert Result (user_type_master):', result1);
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.render('./Faculty/registration', { successMsg: "", errorMsg: "User already exists with the given email." });
            } else {
                console.error('Error inserting into user_type_master:', error);
                return res.render('./Faculty/registration', { successMsg: "", errorMsg: "An error occurred while registering the user." });
            }
        }

        // Retrieve the user_type_id
        const idQuery = `SELECT user_type_id FROM user_type_master WHERE user_name = ?`;
        let user_type_id;
        try {
            const [result2] = await facultyDb.execute(idQuery, [email]);
            console.log('Select Result (user_type_id):', result2[0]);
            user_type_id = result2[0].user_type_id; // Get the user_type_id
        } catch (error) {
            console.error('Error retrieving user_type_id:', error);
            return res.render('./Faculty/registration', { successMsg: "", errorMsg: "An error occurred while retrieving user data." });
        }

        // Insert into user_master table
        const userInsertQuery = `
            INSERT INTO user_master (
                first_name,
                middle_name,
                last_name,
                email_id,
                contact_no,
                pan_card_no,
                addhar_no,
                emp_id,
                institution_id,
                dept_id,
                user_type_id,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'inactive')
        `;

        try {
            const [result] = await facultyDb.execute(userInsertQuery, [
                firstName,
                middleName,
                lastName,
                email,
                contact,
                panCard,
                aadhaar,
                employeeId,
                instituteId,
                departmentId,
                user_type_id
            ]);
            console.log('Insert Result (user_master):', result);
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.render('./Faculty/registration', { successMsg: "", errorMsg: "Duplicate entry detected. Please ensure unique values  PAN, and Aadhaar." });
            } else if (error.code === 'ER_NO_REFERENCED_ROW_2') {
                return res.render('./Faculty/registration', { successMsg: "", errorMsg: "Invalid institution or department ID." });
            } else {
                console.error('Error inserting into user_master:', error);
                return res.render('./Faculty/registration', { successMsg: "", errorMsg: "An error occurred while saving user details." });
            }
        }

        res.redirect(`/faculty/wait?email=${encodeURIComponent(email)}`);

    } catch (error) {
        console.error('Unexpected Error:', error);
        res.status(500).render('./Faculty/registration', { successMsg: "", errorMsg: "Internal Server Error." });
    }
});

// Endpoint for rendering the wait.ejs page
router.get("/wait", (req, res) => {
    const email = req.query.email; // Get the email from query parameters

    if (!email) {
        return res.status(400).send('Email is required to check the approval status.');
    }

    // Render the wait page
    return res.render('./Faculty/wait', { email });
});




// Fetch parameters based on criteria
router.get('/get-parameters/:criteriaId', async (req, res) => {
    const criteriaId = req.params.criteriaId;
    try {
        const [rows] = await facultyDb.execute('SELECT c_parameter_id, parameter_description FROM c_parameter_master WHERE criteria_id = ? AND status = "active"', [criteriaId]);
        res.json({ parameters: rows });
    } catch (error) {
        console.error('Error fetching parameters:', error);
        res.status(500).send('Internal Server Error');
    }
});


router.get("/dashboard", async(req, res) =>{
    res.render("./Faculty/appraisal")
})
router.get('/reset-password', (req, res) => {
    const user_id = req.query.user_id;
    res.render('./Faculty/reset-password', { user_id });
});

router.post('/reset-password', async (req, res) => {
    const user_id = req.body.user_id;
    const newPassword = req.body.newPassword;
    const confirmPassword = req.body.confirmPassword;
    console.log(confirmPassword, newPassword, user_id);

    if (newPassword === confirmPassword) {
        try {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(newPassword, salt);

            const result = await facultyDb.query(
                'UPDATE user_type_master SET password = ? WHERE user_name = ?',
                [hashedPassword, user_id]);
            
            

            res.redirect(`/Faculty/login?message=Password changed successfully!&username=${encodeURIComponent(user_id)}`);
        } catch (err) {
            console.error(err);
            res.status(500).send('Server error');
        }
    } else {
        res.render('reset-password', { user_id, error: 'Passwords do not match. Please try again.' });
    }
});

router.get('/criteria-status', async (req, res) => {
    console.log("criteria-status");
    const successMsg = req.query.successMsg || "";
    try {
        // Get user type ID from the request
        const userTypeId = req.user.user_id;
        if (!userTypeId) {
            return res.status(400).send('User type ID is required');
        }

        // Query to get the user ID based on the user type ID
        const sql = `SELECT user_id FROM user_master WHERE user_type_id = ?`;
        const result = await facultyDb.query(sql, [userTypeId]);
        console.log('User Query Result:', result);

        if (result.length === 0) {
            return res.status(404).send('User not found');
        }

        const userId = result[0][0].user_id;
        console.log('User ID:', userId);

        // SQL query to get criteria status and actions without checking self_appraisal_score status
        const query2 = `
            SELECT
                c.criteria_id AS 'Criteria Number',
                c.criteria_description AS 'Criteria Name',
                CASE
                    WHEN MAX(sas.record_id) IS NOT NULL THEN 'Applied'
                    ELSE 'Not Applied'
                END AS 'Self-Appraisal Status',
                CASE
                    WHEN MAX(cm.record_id) IS NOT NULL THEN 'Reviewed'
                    ELSE 'Not Reviewed'
                END AS 'Committee Status'
            FROM criteria_master c
            LEFT JOIN c_parameter_master p
                ON c.criteria_id = p.criteria_id
            LEFT JOIN self_appraisal_score_master sas
                ON p.c_parameter_id = sas.c_parameter_id AND sas.user_id = ?
            LEFT JOIN committee_master cm
                ON p.c_parameter_id = cm.c_parameter_id AND cm.user_id_employee = ? AND cm.status = 'active'
            WHERE c.status = 'active'
            GROUP BY c.criteria_id, c.criteria_description;
        `;

        // Execute the query with the user ID
        const results2 = await facultyDb.query(query2, [userId, userId]);
        console.log('Criteria Results:', results2[0]);

        if (results2.length === 0) {
            console.log('No criteria data found');
        }

        // Render the results in the view
        res.render('./Faculty/criteria-status', { userId, data: results2[0], successMsg });

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});
router.get("/appraisalnum", async (req, res) => {
    console.log(req.user.user_id)
    try {
        const [institute_id] = await facultyDb.query('select institution_id from user_master where user_type_id = ?', [req.user.user_id]);
        console.log(institute_id);
        const institute = institute_id[0].institution_id;
        const [results] = await facultyDb.query(`
            SELECT am.* 
            FROM appraisal_master am
            JOIN appraisal_departments ad ON am.appraisal_id = ad.appraisal_id
            WHERE ad.institution_id = ? AND am.status = 'active'
        `, [institute]);
        res.render('./Faculty/dashboard3', { data: results });
    } catch (error) {
        console.error('Error fetching appraisal number:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post("/apply", upload.any(), async (req, res) => {
    if (!req.user) {
        return res.status(401).send('Access denied. No token provided.');
    }

    const userTypeId = req.user.user_id;
    const criteriaId = req.body.criteriaId;

    try {
        // Fetch user ID based on userTypeId
        const [userResults] = await facultyDb.query('SELECT user_id FROM user_master WHERE user_type_id = ?', [userTypeId]);
        
        if (userResults.length === 0) {
            return res.status(404).send('User not found');
        }

        const userId = userResults[0].user_id;
        const marksData = [];
        const documentData = {};

        // Prepare data for self_appraisal_score_master
        for (const param in req.body) {
            if (param.startsWith('self_approved_')) {
                const paramId = param.replace('self_approved_', '');
                const marks = parseInt(req.body[param], 10);
                const noProof = req.body[`no_proof_${paramId}`] ? 'no proof' : 'proof'; // Check if 'no proof' is checked
                if (!isNaN(marks)) {
                    marksData.push([userId, marks, paramId, 'inactive', noProof]);
                }
            }
        }

        // Insert self-approved marks one by one
        for (const mark of marksData) {
            await facultyDb.query('INSERT INTO self_appraisal_score_master (user_id, marks_by_emp, c_parameter_id, status, supportive_document) VALUES (?, ?, ?, ?, ?)', mark);
        }

        // Prepare data for document_master
        req.files.forEach(file => {
            const paramIdMatch = file.fieldname.match(/^documents_(C_PARA\d+)\[\]$/);
            const paramId = paramIdMatch ? paramIdMatch[1] : null;
            if (paramId) {
                const docPath = file.path.replace(/\\/g, '/').replace(/^public\//, '');
                if (!documentData[paramId]) {
                    documentData[paramId] = [];
                }
                documentData[paramId].push(docPath);
            } else {
                console.error('Invalid parameter ID in field name:', file.fieldname);
            }
        });

        // Insert documents one by one with sequential document count
        for (const paramId in documentData) {
            const docArray = documentData[paramId];
            let docCount = 1; // Start doc count from 1 for each parameter
            for (const docPath of docArray) {
                await facultyDb.query('INSERT INTO document_master (user_id, c_parameter_id, doc_count, doc_link, location, status) VALUES (?, ?, ?, ?, ?, ?)', [userId, paramId, docCount, docPath, 'uploads/', 'active']);
                docCount++; // Increment doc count for each document
            }
        }

        const successMsg = 'Documents and marks uploaded successfully';
        res.redirect(`/faculty/criteria-status?successMsg=${successMsg}`);
    } catch (error) {
        console.error('Error processing request:', error);
        res.status(500).send('Internal Server Error');
    }
});


router.get('/apply', async (req, res) => {
    const { criteriaId } = req.query;

    try {
        // Fetch criteria details
        const criteriaQuery = `
            SELECT c.criteria_description AS 'Criteria Name', cp.*
            FROM criteria_master c
            JOIN c_parameter_master cp ON c.criteria_id = cp.criteria_id
            WHERE c.criteria_id = ?
        `;
        const parameters = await facultyDb.query(criteriaQuery, [criteriaId]);
        const CriteriaName = parameters[0][0]['Criteria Name'];        console.log(CriteriaName);
        // Render EJS template
        res.render('faculty/apply', { parameters: parameters[0], criteriaId,CriteriaName });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});



router.get('/view', async (req, res) => {
    const userTypeId = req.user.user_id;
    const { criteriaId } = req.query;
   
    try {
        const [userResults] = await facultyDb.query('SELECT user_id FROM user_master WHERE user_type_id = ?', [userTypeId]);
        
        if (userResults.length === 0) {
            return res.status(404).send('User not found');
        }

        const userId = userResults[0].user_id;
        const criteriaQuery = `
        SELECT c.criteria_description AS 'criteriaName', cp.*, sas.marks_by_emp, COALESCE(cm.comm_score, 'Pending') AS committeeScore
        FROM criteria_master c
        JOIN c_parameter_master cp ON c.criteria_id = cp.criteria_id
        LEFT JOIN self_appraisal_score_master sas ON cp.c_parameter_id = sas.c_parameter_id AND sas.user_id = ?
        LEFT JOIN committee_master cm ON sas.record_id = cm.record_id
        WHERE c.criteria_id = ?
    `;
        const parameters = await facultyDb.query(criteriaQuery, [userId, criteriaId]);

        // Fetch documents uploaded by the logged-in faculty
        const documentQuery = `
            SELECT d.document_id, d.doc_link AS document_path, d.c_parameter_id
            FROM document_master d
            JOIN c_parameter_master cp ON d.c_parameter_id = cp.c_parameter_id
            WHERE cp.criteria_id = ? AND d.user_id = ?
        `;
        const documents = await facultyDb.query(documentQuery, [criteriaId, userId]);

        const criteriaName = parameters[0][0].criteriaName;

        // Render EJS template
        res.render('faculty/view', { parameters: parameters[0], documents: documents[0], criteriaId, criteriaName });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});


router.get('/edit', async (req, res) => {
    const userTypeId = req.user.user_id;
    const { criteriaId } = req.query;
   
    try {
        const [userResults] = await facultyDb.query('SELECT user_id FROM user_master WHERE user_type_id = ?', [userTypeId]);
        
        if (userResults.length === 0) {
            return res.status(404).send('User not found');
        }

        const userId = userResults[0].user_id;
        const criteriaQuery = `
        SELECT c.criteria_description AS 'criteriaName', cp.*, sas.marks_by_emp, COALESCE(cm.comm_score, 'Pending') AS committeeScore
        FROM criteria_master c
        JOIN c_parameter_master cp ON c.criteria_id = cp.criteria_id
        LEFT JOIN self_appraisal_score_master sas ON cp.c_parameter_id = sas.c_parameter_id AND sas.user_id = ?
        LEFT JOIN committee_master cm ON sas.record_id = cm.record_id
        WHERE c.criteria_id = ?
    `;
        const parameters = await facultyDb.query(criteriaQuery, [userId, criteriaId]);

        // Fetch documents uploaded by the logged-in faculty
        const documentQuery = `
            SELECT d.document_id, d.doc_link AS document_path, d.c_parameter_id
            FROM document_master d
            JOIN c_parameter_master cp ON d.c_parameter_id = cp.c_parameter_id
            WHERE cp.criteria_id = ? AND d.user_id = ?
        `;
        const documents = await facultyDb.query(documentQuery, [criteriaId, userId]);

        const criteriaName = parameters[0][0].criteriaName;

        // Render EJS template
        res.render('faculty/edit', { parameters: parameters[0], documents: documents[0], criteriaId, criteriaName });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

router.post('/submit-criteria-status', async (req, res) => {
    if (!req.user) {
        return res.status(401).send('Access denied. No token provided.');
    }

    const userTypeId =req.user.user_id;

    try {
        // Fetch user ID based on userTypeId
        const [userResults] = await facultyDb.query('SELECT user_id FROM user_master WHERE user_type_id = ?', [userTypeId]);

        if (userResults.length === 0) {
            return res.status(404).send('User not found');
        }

        const userId = userResults[0].user_id;
        const criteriaStatusData = req.body.criteriaStatusData; // Assuming this is an array of criteria status data
        const marksData = [];

        // Process criteria statuses
        for (const criteria of criteriaStatusData) {
            const criteriaId = criteria.criteriaId;
            const status = criteria.status;

            if (status === 'Applied') {
                // Update status for parameter in self_appraisal to 'active'
                await facultyDb.query(
                    'UPDATE self_appraisal_score_master SET status = ? WHERE user_id = ? AND status="inactive"',
                    ['active', userId]
                );
                console.log(`Updated status for criteria ${criteriaId} to 'active'`);
            } else if (status === 'Not Applied') {
                // Get all parameter IDs for the criteria
                const [parameterResults] = await facultyDb.query(
                    'SELECT c_parameter_id FROM c_parameter_master WHERE criteria_id = ?',
                    [criteriaId]
                );

                if (parameterResults.length === 0) {
                    console.log(`No parameters found for criteria ${criteriaId}`);
                    continue; // Skip if no parameters are found
                }

                // Prepare data to insert
                for (const parameter of parameterResults) {
                    const parameterId = parameter.c_parameter_id;
                    marksData.push([userId, 0, parameterId, 'active', 'no proof']);
                    console.log(`Prepared marks data: [userId: ${userId}, marks_by_emp: 0, c_parameter_id: ${parameterId}, status: 'active', supportive_document: 'no proof']`);
                }
            }
        }

        // Insert marks data for 'Not Applied' criteria
        for (const mark of marksData) {
            await facultyDb.query(
                'INSERT INTO self_appraisal_score_master (user_id, marks_by_emp, c_parameter_id, status, supportive_document) VALUES (?, ?, ?, ?, ?)',
                mark
            );
            console.log(`Inserted Marks Data: ${mark}`);
        }

        const successMsg = 'Criteria status submitted successfully';
        res.json({
        success: true,
        message: 'Data processed successfully'
    });

        
    } catch (error) {
        console.error('Error processing request:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.get('/forget-password', (req, res) => {

    res.render("./faculty/forgetPassword",{errorMessage:""})
});

router.post('/forget-password', async(req, res) => {
    const username=req.body.username
    try {
        const result = await facultyDb.query(
            'SELECT * FROM user_type_master WHERE user_name = ?  AND user_type_type= "employee"',
            [username]
        );
        const user = result[0];
        console.log('User from DB:',user);

        if (user.length > 0) {
            const status = user[0].status; // Assuming `status` is a field in `user_type_master`
            const user_id = user[0].user_type_id;
            if (status === 'inactive') {
                res.redirect(`/faculty/wait?email=${encodeURIComponent(username)}`);
            } 
            else{
             // Generate a 6-digit OTP
            console.log("Generating")
             const otp = crypto.randomInt(100000, 999999).toString();

             // Store OTP in OTP_MASTER table
             await facultyDb.query(
                 'INSERT INTO OTP_MASTER (OTP_ID, EMAIL_ID, OTP, STATUS) VALUES (?, ?, ?, "active")',
                 [crypto.randomBytes(16).toString('hex'), username, otp]
             );
 
             // Send OTP to user's email
             let mailOptions = {
                 from: process.env.EMAIL_USERNAME,
                 to: username, // assuming username is the user's email
                 subject: 'Password Reset ',
                 text: `Your OTP for changing password is  ${otp}`
             };
 
             transporter.sendMail(mailOptions, function(error, info){
                 if (error) {
                     console.log(error);
                 } else {
                     console.log('Email sent: ' + info.response);
                 }
             });
            res.render("./faculty/verify",{username:username})}
        } else {
            res.render("./faculty/forgetPassword",{errorMessage:"User not found"});
        }
    } catch (error) {
        console.error(error);
        res.render("./faculty/forgetPassword",{errorMessage:error});    }
    
});

router.post('/verifyOtp', async function (req, res) {
    const username = req.body.username;
    const otp = req.body.otp;
    console.log('Username:', username);
    console.log('OTP:', otp);
    try {
        const q = await facultyDb.query(`SELECT otp, timestamp FROM otp_master WHERE email_id = ?
        AND status = 'active' ORDER BY timestamp DESC LIMIT 1;`, [username]
        )
        console.log(q);
        const otpData = q[0][0n];
        const oldOTP= otpData.otp;
        const timestamp = otpData.timestamp;
    
        console.log(oldOTP, timestamp);
        const currentTime = new Date().getTime();
        if (currentTime - timestamp > 300000) {
            console.log('The OTP has expired. Please request a new OTP.')
            return res.render('./Principal/login', { error: 'The OTP has expired. Please request a new OTP.' });
        }
        if (String(oldOTP) !== String(otp)) {
            console.log('error', 'Invalid OTP.');
            return res.render('./Principal/verify', { error: 'Invalid OTP.', username });
        }
        else {
            console.log('success', 'OTP verified successfully.');
            const [result] = await facultyDb.query(
                'UPDATE otp_master SET status = "inactive" WHERE email_id = ? AND otp = ?',
                [username, otp]
            );
            res.redirect(`/faculty/reset-password?user_id=${encodeURIComponent(username)}`);
        }}
        catch (err) {console.log('error', err)}})


export default router;
