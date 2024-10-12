import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import express from 'express';
import jwt from "jsonwebtoken";
import Razorpay from 'razorpay';
import facultyDb from '../faculty.db.js';
import { authorizeRole, getCriteriaWithParameters, getParametersByCriteriaId, jwtMiddleware, sendApprovalEmail, sendCommitteeEmails, transporter } from '../service.js';
const router = express.Router();
router.use(jwtMiddleware);


const razorpayInstance = new Razorpay({
    key_id: process.env.RAZORPAY_ID_KEY,
    key_secret: process.env.RAZORPAY_SECRET_KEY,
});

router.get('/payment', (req, res) => {
    const email = "apurva3barthwal@gmail.com"; // You can fetch this dynamically
    const institute_id = "INS8"; // You can fetch this dynamically

    res.render('principal/payment', { 
        email, 
        institute_id, 
        razorpayId: process.env.RAZORPAY_ID_KEY 
    });
});

router.post('/payment', async (req, res) => {
    const email = "apurva3barthwal@gmail.com"; // You can fetch this dynamically
    const institute_id = "INS8"; // Replace with dynamic values if needed

    try {
        // Create an order in Razorpay
        const options = {
            amount: 2000000,  // Amount in paise (e.g., 20,000 INR)
            currency: "INR",
            receipt: `order_receipt_${Date.now()}`,  // Unique identifier for this order
        };
        console.log(options.amount)
        const order = await razorpayInstance.orders.create(options);

        // Store the order details in MySQL
        const insertOrderQuery = `
            INSERT INTO payment_orders (order_id,amount, principal_email, institution_id, payment_status)
            VALUES (?, ?,?, ?, 'created')
        `;
        await facultyDb.execute(insertOrderQuery, [order.id,options.amount, email, institute_id,]);

        // Send the order details to the client
        res.json({
            amount: options.amount,
            currency: options.currency,
            orderId: order.id
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: "An error occurred while creating the order." });
    }
});
router.post('/verify-payment', async (req, res) => {
    const { order_id, payment_id, razorpay_signature } = req.body;

    // Verify payment using Razorpay's API
    try {
        const body = order_id + "|" + payment_id;
      
        const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_SECRET_KEY)
                                       .update(body.toString())
                                       .digest('hex');

        if (expectedSignature === razorpay_signature) {
            // Update payment status in the database
            const updatePaymentStatusQuery = `
                UPDATE payment_orders
                SET payment_status = 'paid'
                WHERE order_id = ?
            `;
            await facultyDb.execute(updatePaymentStatusQuery, [order_id]);

            res.send('Payment  Sucessfull Successfully');
        } else {
            res.status(400).send('Payment verification failed');
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).send("An error occurred while verifying payment.");
    }
});




router.get('/login', (req, res) => {
    const message = req.query.message || '';
    const error = req.query.error || '';
    const username = req.query.username || '';
    res.render('./principal/login', { message, error, username });
});












router.get('/register', (req, res) => {

    res.render('./Principal/registration',{successMsg:"",errorMsg:""});
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
        instituteName,
        departmentName
    } = req.body;

    console.log(firstName, middleName, lastName, email, contact, dob, panCard, aadhaar, employeeId, instituteName, departmentName);
    try {
        //Check if PAN, Aadhaar, and contact already exist in user_master
        const checkUniqueFieldsQuery = `
            SELECT 
                CASE WHEN EXISTS(SELECT 1 FROM user_master WHERE pan_card_no = ?) THEN 'pan' ELSE NULL END AS panExists,
                CASE WHEN EXISTS(SELECT 1 FROM user_master WHERE addhar_no = ?) THEN 'aadhaar' ELSE NULL END AS aadhaarExists,
                CASE WHEN EXISTS(SELECT 1 FROM user_master WHERE contact_no = ?) THEN 'contact' ELSE NULL END AS contactExists
        `;
        try {
            const [uniqueFieldsResult] = await facultyDb.execute(checkUniqueFieldsQuery, [panCard, aadhaar, contact]);
            const { panExists, aadhaarExists, contactExists } = uniqueFieldsResult[0];

            if (panExists) {
                return res.render('./Principal/registration', { successMsg: "", errorMsg: "PAN Card already exists." });
            } else if (aadhaarExists) {
                return res.render('./Principal/registration', { successMsg: "", errorMsg: "Aadhaar already exists." });
            } else if (contactExists) {
                return res.render('./Principal/registration', { successMsg: "", errorMsg: "Contact number already exists." });
            }
        } catch (error) {
            console.error('Error checking PAN, Aadhaar, and contact:', error);
            return res.render('./Principal/registration', { successMsg: "", errorMsg: "An error occurred while checking unique fields." });
        }






        const password = "Misfits";
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        //Check if the user already exists in user_type_master
        const checkUserQuery = `SELECT user_type_id FROM user_type_master WHERE user_name = ?`;
        let user_type_id;
        try {
            const [userResult] = await facultyDb.execute(checkUserQuery, [email]);
            if (userResult.length > 0) {
                return res.render('./Principal/registration', { successMsg: "", errorMsg: "User already exists with the given email." });
            } else {
                // Insert into user_type_master
                const insertUserTypeQuery = `INSERT INTO user_type_master (user_name, password, user_type_type, status) VALUES (?, ?, ?, ?)`;
                const [insertUserTypeResult] = await facultyDb.execute(insertUserTypeQuery, [email, hashedPassword, 'admin', 'inactive']);
                console.log('Insert Result (user_type_master):', insertUserTypeResult);

                // Retrieve the user_type_id after insertion
                const [userIdResult] = await facultyDb.execute(checkUserQuery, [email]);
                user_type_id = userIdResult[0].user_type_id;
            }
        } catch (error) {
            console.error('Error handling user_type_master:', error);
            return res.render('./Principal/registration', { successMsg: "", errorMsg: "An error occurred while checking user email." });
        }

        // Check if the institute exists in institution_master
        let institutionId;
        const checkInstituteQuery = `SELECT institution_id FROM institution_master WHERE institution_name = ?`;
        try {
            const [instituteResult] = await facultyDb.execute(checkInstituteQuery, [instituteName]);
            if (instituteResult.length > 0) {
                institutionId = instituteResult[0].institution_id;
            } else {
                // Insert institute if not found
                const insertInstituteQuery = `INSERT INTO institution_master (institution_name) VALUES (?)`;
                const [insertInstituteResult] = await facultyDb.execute(insertInstituteQuery, [instituteName]);
                console.log('Insert Result (institution_master):', insertInstituteResult);

                // Retrieve the newly inserted institute ID
                const [newInstituteResult] = await facultyDb.execute(checkInstituteQuery, [instituteName]);
                institutionId = newInstituteResult[0].institution_id;
            }
        } catch (error) {
            console.error('Error handling institution_master:', error);
            return res.render('./Principal/registration', { successMsg: "", errorMsg: "An error occurred while processing the institution." });
        }

        // Check if the department exists in department_master
        let departmentId;
        const checkDepartmentQuery = `SELECT dept_id FROM department_master WHERE department_name = ? AND institution_id = ?`;
        try {
            const [departmentResult] = await facultyDb.execute(checkDepartmentQuery, [departmentName, institutionId]);
            if (departmentResult.length > 0) {
                departmentId = departmentResult[0].dept_id;
            } else {
                // Insert department if not found
                const insertDepartmentQuery = `INSERT INTO department_master (department_name, institution_id, user_name) VALUES (?, ?, ?)`;
                const [insertDepartmentResult] = await facultyDb.execute(insertDepartmentQuery, [departmentName, institutionId, user_type_id]);
                console.log('Insert Result (department_master):', insertDepartmentResult);

                // Retrieve the newly inserted department ID
                const [newDepartmentResult] = await facultyDb.execute(checkDepartmentQuery, [departmentName, institutionId]);
                departmentId = newDepartmentResult[0].dept_id;
            }
        } catch (error) {
            console.error('Error handling department_master:', error);
            return res.render('./Principal/registration', { successMsg: "", errorMsg: "An error occurred while processing the department." });
        }

        // Insert into user_master with institution_id and department_id
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
            const [insertUserResult] = await facultyDb.execute(userInsertQuery, [
                firstName,
                middleName,
                lastName,
                email,
                contact,
                panCard,
                aadhaar,
                employeeId,
                institutionId, // Use the retrieved institution ID
                departmentId,  // Use the retrieved department ID
                user_type_id
            ]);
            console.log('Insert Result (user_master):', insertUserResult);
        } catch (error) {
            console.error('Error inserting into user_master:', error);
            return res.render('./Principal/registration', { successMsg: "", errorMsg: "An error occurred while saving user details." });
        }

        res.redirect(`/principal/wait?email=${encodeURIComponent(email)}&instituteName=${encodeURIComponent(instituteName)}`);
    } catch (error) {
        console.error('Unexpected Error:', error);
        res.status(500).render('./Principal/registration', { successMsg: "", errorMsg: "Internal Server Error." });
    }
});

router.get('/wait', (req, res) => {
    const email = req.query.email;
    const instituteName = req.query.instituteName;
    
    res.render('principal/wait', {
        email: email,
        instituteName: instituteName
    });
});






// JWT Middleware
router.use(async (req, res, next) => {
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            req.user = user;
            console.log(user.institution_id)

            if (user.role === 'admin') {
                const [pendingRequests] = await facultyDb.query(
                    'SELECT COUNT(*) AS count FROM user_master WHERE status = "inactive" AND institution_id =  ?',
                    [user.institution_id]
                );
                console.log(pendingRequests)
                res.locals.pendingRequestsCount = pendingRequests[0].count;
                console.log("pending requests count",res.locals.pendingRequestsCount);
            } else {
                res.locals.pendingRequestsCount = 0;
            }

            res.locals.loggedIn = true;
        } catch (err) {
            console.error('JWT verification error:', err);
            res.clearCookie('token');
            res.locals.loggedIn = false;
            res.locals.pendingRequestsCount = 0;
        }
    } else {
        res.locals.loggedIn = false;
        res.locals.pendingRequestsCount = 0;
    }
    next();
});

//2fa verfication 


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
            const userSql = await facultyDb.query(
                'SELECT * FROM user_type_master WHERE user_name = ? AND user_type_type= "admin"', [username]);
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
            res.redirect('/principal/dashboard');
        }
    } catch (error) {
        console.error(error);
    }
})
router.post('/login', async (req, res) => {
    
    const username = req.body.uname;
    const password = req.body.password;
    console.log("Principal", username, password);

    try {
        const result = await facultyDb.query(
            'SELECT * FROM user_type_master WHERE user_name = ?  AND user_type_type= "admin"',
            [username]
        );
        const user = result[0];
        console.log('User from DB:',user);

        if (user.length > 0) {
            const status = user[0].status; // Assuming `status` is a field in `user_type_master`
            const hashedPassword = user[0].password; // Assuming `password` is a field in `user_type_master`
            const user_id = user[0].user_type_id;
            const passwordMatch = await bcrypt.compare(password, hashedPassword);
            const isDefaultPassword = await bcrypt.compare('Misfits', hashedPassword);
            if (status === 'inactive') {
                res.redirect(`/principal/wait?email=${encodeURIComponent(username)}`);
            } 
            else if (isDefaultPassword) {
                res.redirect(`/principal/reset-password?user_id=${user_id}`);
            }
            else if (!passwordMatch) {
                res.render('./Principal/login', { error: 'Invalid password', message: '', username: username });
            }else{
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
                 from: process.env.SMTP_MAIL,
                 to: username, // assuming username is the user's email
                 subject: '2FA for Principal Login  ',
                 text: `Your OTP is ${otp}`
             };
 
             transporter.sendMail(mailOptions, function(error, info){
                 if (error) {
                     console.log(error);
                 } else {
                     console.log('Email sent: ' + info.response);
                 }
             });
            res.render("./principal/verify",{username:username})}
        } else {
            res.render("./Principal/login", { error: "User Doest not Exists." });
        }
    } catch (error) {
        console.error(error);
        res.render("./Principal/login", { error: "An error occurred. Please try again." ,message:"",username:username});
    }
});
router.get('/reset-password', (req, res) => {
    const user_id = req.query.user_id;
    res.render('./principal/reset-password', { user_id });
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
                'UPDATE user_type_master SET password = ? WHERE user_type_id = ?',
                [hashedPassword, user_id]);
            
            // Get the username from the database using the user_id
            const userResult = await facultyDb.query(
                'SELECT user_name FROM user_type_master WHERE user_type_id = ?',
                [user_id]
            );
            const username = userResult[0][0].user_name;

            res.redirect(`/principal/login?message=Password changed successfully!&username=${encodeURIComponent(username)}`);
        } catch (err) {
            console.error(err);
            res.status(500).send('Server error');
        }
    } else {
        res.render('reset-password', { user_id, error: 'Passwords do not match. Please try again.' });
    }
});

router.use(authorizeRole('admin'));



    
router.get('/dashboard', async(req, res) => {
   
try {
            const principalId = req.user.id; // Assuming you have authentication set up
           
            const instituteId = req.user.institution_id
    
            // Fetch all active employees for the principal's institute
            const activeEmployeesQuery = `
            SELECT um.user_id, um.email_id, um.first_name, um.last_name, dm.department_name, um.emp_id, um.timestamp as start_date,utm.user_type_type as type ,utm.status
            FROM user_master um
            JOIN department_master dm ON um.dept_id = dm.dept_id
            JOIN user_type_master utm ON um.user_type_id = utm.user_type_id
            WHERE um.institution_id = ? AND um.status = 'active' AND (utm.user_type_type = 'employee' OR utm.user_type_type = 'committee') ;
        `;
            const [employees] = await facultyDb.execute(activeEmployeesQuery, [instituteId]);
    
            res.render('./Principal/emptable',{employees});        }
        catch (err) {
            console.error(err);
        }
        
        });
    



router.get('/approvals', async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).send('Access denied.');

    console.log(req.user.institution_id);
    try {
        const [pendingRequests] = await facultyDb.query(
            `SELECT user_id, first_name, middle_name, last_name, email_id, contact_no, emp_id
            FROM user_master
            WHERE status = "inactive" AND institution_id = ?`,
            [req.user.institution_id]
        );

        res.render('./Principal/approvals', { pendingRequests });
    } catch (error) {
        console.error('Error fetching pending requests:', error);
        res.status(500).send('Internal Server Error');
    }
});
router.post('/approve', async (req, res) => {
    // Check if the user has admin privileges
    if (req.user.role !== 'admin') return res.status(403).send('Access denied.');

    const { user_id } = req.body;

    try {
        // Fetch user details using user_id
        const [user] = await facultyDb.query(
            'SELECT user_id, first_name, last_name, email_id FROM user_master WHERE user_id = ?',
            [user_id]
        );

        if (user.length === 0) return res.status(404).send('User not found.');

        const email = user[0].email_id; // Extract the email from the fetched user details

        // Update the user's status to "active" in the user_type_master table using email
        const [result1] = await facultyDb.query(
            'UPDATE user_type_master SET status = "active" WHERE user_name = ?',
            [email]
        );

        // Update the user's status to "active" in the user_master table using user_id
        const [result] = await facultyDb.query(
            'UPDATE user_master SET status = "active" WHERE user_id = ?',
            [user_id]
        );

        if (result.affectedRows > 0 && result1.affectedRows > 0) {
            // Send email notification to the user about approval
            await sendApprovalEmail(user[0]);

            // Redirect with a success message to the principal's approvals page
            res.redirect('/principal/approvals');
        } else {
            res.status(404).send('User not found or update failed.');
        }
    } catch (error) {
        console.error('Error approving request:', error);
        res.status(500).send('Internal Server Error');
    }
});




// Route to render the page for active employees
router.get('/createCommittee',async (req, res) => {
    try {
        const principalId = req.user.id; // Assuming you have authentication set up
       
        const instituteId = req.user.institution_id

        // Fetch all active employees for the principal's institute
        const activeEmployeesQuery = `
        SELECT um.user_id, um.email_id, um.first_name, um.last_name, dm.department_name, um.emp_id, um.timestamp as start_date
        FROM user_master um
        JOIN department_master dm ON um.dept_id = dm.dept_id
        JOIN user_type_master utm ON um.user_type_id = utm.user_type_id
        WHERE um.institution_id = ? AND um.status = 'active' AND utm.user_type_type = 'employee'
    `;
        const [employees] = await facultyDb.execute(activeEmployeesQuery, [instituteId]);

        res.render('./principal/createCommittee', { employees });
    }
    catch (err) {
        console.error(err);
    }
    });


router.get('/appraisal/createCommittee/:appraisalId', async (req, res) => {
        try {
            const principalId = req.user.id; // Assuming you have authentication set up
            const appraisalId = req.params.appraisalId;
            const instituteId = req.user.institution_id;
            
            // Fetch all active employees for the principal's institute
            const activeEmployeesQuery = `
                SELECT um.user_id, um.email_id, um.first_name, um.last_name, dm.department_name, um.emp_id, um.timestamp as start_date
                FROM user_master um
                JOIN department_master dm ON um.dept_id = dm.dept_id
                JOIN user_type_master utm ON um.user_type_id = utm.user_type_id
                WHERE um.institution_id = ? AND um.status = 'active' AND utm.user_type_type = 'employee'
            `;
            const [employees] = await facultyDb.execute(activeEmployeesQuery, [instituteId]);
            
            // Fetch the appraisal cycle name
            const appraisalSql = `SELECT appraisal_cycle_name FROM appraisal_master WHERE appraisal_id = ?`;
            const [appraisalCycleRows] = await facultyDb.execute(appraisalSql, [appraisalId]); // Use appraisalId here
    
            // Extract the appraisal cycle name from the result
            const appraisal_cycle_name = appraisalCycleRows.length > 0 ? appraisalCycleRows[0].appraisal_cycle_name : 'Unknown';
            console.log(employees, ', ',appraisal_cycle_name);
            // Render the page with the employees and the appraisal cycle name
            res.render('./principal/appraisalCommitteeMember', { employees, appraisal_cycle_name, appraisal_id: appraisalId });
        }
        catch (err) {
            console.error(err);
            res.status(500).send('Server Error');
        }
});
    

router.post('/appraisal/submit-committee/:appraisal_id', async (req, res) => {
        const { committeeMembers, start_date,end_date } = req.body;
        const principalId = req.user.user_id;
        const instituteId = req.user.institution_id;
        const appraisalId = req.params.appraisal_id;
        // Check for missing data
        if (!committeeMembers || committeeMembers.length === 0 ) {
            return res.status(400).json({ success: false, message: "Missing committee members or tenure" });
        }
    
        // Get current date for start_date
        const startDate =start_date;
    
        // Calculate endDate by adding the tenure (in years) to the start_date
        const endDate = end_date;
        console.log(committeeMembers, startDate, endDate);
    
        // Begin transaction
        const connection = await facultyDb.getConnection();
        try {
            await connection.beginTransaction();
    
            // Insert each committee member into committee_member_master
            const committeeMembersDetails = []; // Array to store details for sending emails
    
            for (const memberId of committeeMembers) {
                // Insert each committee member into committee_member_master
                const insertQuery = `
                    INSERT INTO committee_member_master (user_id, institution_id, start_date, end_date,appraisal_id) 
                    VALUES (?, ?, ?, ?,?);
                `;
                await connection.query(insertQuery, [memberId, instituteId, startDate, endDate,appraisalId]);
    
                // Fetch user details for email
                const selectUserDetailsQuery = `
                SELECT um.user_id, um.email_id, um.first_name, um.last_name, dm.department_name, im.institution_name
                FROM user_master um
                JOIN department_master dm ON um.dept_id = dm.dept_id
                JOIN institution_master im ON um.institution_id = im.institution_id
                WHERE um.user_id = ?;
                `;
                const [userDetails] = await connection.query(selectUserDetailsQuery, [memberId]);
                if (userDetails.length > 0) {
                    const memberDetail = userDetails[0];
                    memberDetail.start_date = startDate;
                    memberDetail.end_date = endDate;
                    committeeMembersDetails.push(memberDetail);
                }
            }
            console.log(committeeMembersDetails)
    
            // Update user_type_type in user_type_master
            const userTypeIdsArray = [];
            for (const memberId of committeeMembers) {
                const selectQuery = `
                    SELECT user_type_id 
                    FROM user_master 
                    WHERE user_id = ?;
                `;
                const [userTypeIdRows] = await connection.query(selectQuery, [memberId]);
    
                if (userTypeIdRows.length > 0) {
                    userTypeIdsArray.push(userTypeIdRows[0].user_type_id);
                }
            }
    
            for (const userTypeId of userTypeIdsArray) {
                const updateQuery = `
                    UPDATE user_type_master 
                    SET user_type_type = 'committee' 
                    WHERE user_type_id = ?;
                `;
                await connection.query(updateQuery, [userTypeId]);
            }
    
            // Commit transaction
            await connection.commit();
    
            // Send emails to the committee members
            await sendCommitteeEmails(committeeMembersDetails);
    
            res.json({ success: true, message: "Committee members submitted and updated successfully!" });
        } catch (err) {
            // Rollback transaction in case of error
            await connection.rollback();
            console.error("Error processing committee submission:", err);
            res.status(500).json({ success: false, message: "Failed to submit committee members" });
        } finally {
            // Release the connection
            connection.release();
        }
});








router.post('/submit-committee', async (req, res) => {
        const { committeeMembers, start_date,end_date } = req.body;
        const principalId = req.user.user_id;
        const instituteId = req.user.institution_id;
    
        // Check for missing data
        if (!committeeMembers || committeeMembers.length === 0 ) {
            return res.status(400).json({ success: false, message: "Missing committee members or tenure" });
        }
    
        // Get current date for start_date
        const startDate =start_date;
    
        // Calculate endDate by adding the tenure (in years) to the start_date
        const endDate = end_date;
        console.log(committeeMembers, startDate, endDate);
    
        // Begin transaction
        const connection = await facultyDb.getConnection();
        try {
            await connection.beginTransaction();
    
            // Insert each committee member into committee_member_master
            const committeeMembersDetails = []; // Array to store details for sending emails
    
            for (const memberId of committeeMembers) {
                // Insert each committee member into committee_member_master
                const insertQuery = `
                    INSERT INTO committee_member_master (user_id, institution_id, start_date, end_date) 
                    VALUES (?, ?, ?, ?);
                `;
                await connection.query(insertQuery, [memberId, instituteId, startDate, endDate]);
    
                // Fetch user details for email
                const selectUserDetailsQuery = `
                SELECT um.user_id, um.email_id, um.first_name, um.last_name, dm.department_name, im.institution_name
                FROM user_master um
                JOIN department_master dm ON um.dept_id = dm.dept_id
                JOIN institution_master im ON um.institution_id = im.institution_id
                WHERE um.user_id = ?;
                `;
                const [userDetails] = await connection.query(selectUserDetailsQuery, [memberId]);
                if (userDetails.length > 0) {
                    const memberDetail = userDetails[0];
                    memberDetail.start_date = startDate;
                    memberDetail.end_date = endDate;
                    committeeMembersDetails.push(memberDetail);
                }
            }
            console.log(committeeMembersDetails)
    
            // Update user_type_type in user_type_master
            const userTypeIdsArray = [];
            for (const memberId of committeeMembers) {
                const selectQuery = `
                    SELECT user_type_id 
                    FROM user_master 
                    WHERE user_id = ?;
                `;
                const [userTypeIdRows] = await connection.query(selectQuery, [memberId]);
    
                if (userTypeIdRows.length > 0) {
                    userTypeIdsArray.push(userTypeIdRows[0].user_type_id);
                }
            }
    
            for (const userTypeId of userTypeIdsArray) {
                const updateQuery = `
                    UPDATE user_type_master 
                    SET user_type_type = 'committee' 
                    WHERE user_type_id = ?;
                `;
                await connection.query(updateQuery, [userTypeId]);
            }
    
            // Commit transaction
            await connection.commit();
    
            // Send emails to the committee members
            await sendCommitteeEmails(committeeMembersDetails);
    
            res.json({ success: true, message: "Committee members submitted and updated successfully!" });
        } catch (err) {
            // Rollback transaction in case of error
            await connection.rollback();
            console.error("Error processing committee submission:", err);
            res.status(500).json({ success: false, message: "Failed to submit committee members" });
        } finally {
            // Release the connection
            connection.release();
        }
    });
// Route to display committee member details
router.get('/editCommittee', async (req, res) => {
    const instituteId = req.user.institution_id; // Assuming the user is a principal and belongs to an institution
    const message = req.query.message || '';
    try {
        // Query to fetch committee member details
        const query = `
            SELECT cm.user_id, u.first_name, u.last_name, u.email_id, cm.start_date, cm.end_date
            FROM committee_member_master cm
            JOIN user_master u ON cm.user_id = u.user_id
            WHERE cm.institution_id = ? and cm.status ="active";
        `;

        const [committeeMembers] = await facultyDb.query(query, [instituteId]);

        // Render the EJS page with the fetched data
        res.render('./principal/committee', { committeeMembers ,message});
    } catch (err) {
        console.error("Error fetching committee members:", err);
        res.status(500).send("Error fetching committee members.");
    }
});

// Route to remove a committee member
router.post('/removeCommitteeMember', async (req, res) => {
    const { user_id } = req.body;

    // Check if user_id is provided
    if (!user_id) {
        return res.status(400).json({ error: 'Valid User ID is required' });
    }

    try {
        // Set the status of the committee member to 'inactive'
        const updateCommitteeMemberStatus = 'UPDATE committee_member_master SET status = "inactive" WHERE user_id = ?';
        const [result] = await facultyDb.query(updateCommitteeMemberStatus, [user_id]);

        if (result.affectedRows === 0) {
            return res.status(500).json({ error: 'Failed to remove committee member' });
        }

        // Get the user_type_id of the user
        const getUserTypeID = 'SELECT user_type_id FROM user_master WHERE user_id = ?';
        const [userTypeID] = await facultyDb.query(getUserTypeID, [user_id]);

        // Check if user_type_id was found
        if (userTypeID.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Set the user_type_type of the user to 'employee'
        const updateUserType = 'UPDATE user_type_master SET user_type_type = "employee" WHERE user_type_id = ?';
        await facultyDb.query(updateUserType, [userTypeID[0].user_type_id]);

        // Send a success response
        res.redirect(`/principal/editCommittee?message=${encodeURIComponent('Successfully removed committee member')}`);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



router.get("/add-departments", (req, res) => {
    
    res.render("./Principal/addDepartment",{success: "",error: ""});
})
router.post("/add-departments", async (req, res) => {
    const { department_name } = req.body;
    const instituteId = req.user.institution_id;
    const userTypeID = req.user.user_id;
    console.log(userTypeID)
    try {
        const [department] = await facultyDb.query(
            'SELECT dept_id FROM department_master WHERE department_name = ? AND institution_id = ?',
            [department_name, instituteId]
        );

        if (department.length > 0) {
            return res.render('./Principal/addDepartment',{success:"",error:'Department already exists'});
        }

        const [result] = await facultyDb.query(
            'INSERT INTO department_master (department_name, institution_id,user_name) VALUES (?, ?,?)',
            [department_name, instituteId,userTypeID]
        );

        if (result.affectedRows > 0) {
            return res.render('./principal/addDepartment',{success:"Successfully Added Department!!!!!",error:''});
        }
        return res.render('./Principal/addDepartment',{success:"",error:'Failed to add department'});


    } catch (error) {
        console.error('Error adding department:', error);
        return res.render('./Principal/addDepartment',{success:"",error:'Internal Server Error'});
    }
})


// Get route to display the list of departments
router.get('/departments', async (req, res) => {
    try {
        // Fetch the active departments
        const [departments] = await facultyDb.query(
            'SELECT * FROM department_master WHERE institution_id = ? AND status="active"',
            [req.user.institution_id]
        );

        // Fetch the removed departments
        const [removedDepartments] = await facultyDb.query(
            'SELECT * FROM department_master WHERE institution_id = ? AND status="inactive"',
            [req.user.institution_id]
        );

        // Render the page with the list of active and removed departments
        res.render('./principal/departments', {
            departments: departments,
            removedDepartments: removedDepartments,  // Pass removed departments
            message: req.query.message || null  // Optional success message after remove
        });
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).send('Internal Server Error');
    }
});


// Post route to remove a department
router.post('/removeDepartment', async (req, res) => {
    
    const departmentId = req.body.dept_id;
    console.log("aaa",
        departmentId);

    try {
        // Remove department from the database (you can also make it soft-delete if needed)
        await facultyDb.query('Update department_master set status="inactive" WHERE dept_id = ?', [departmentId]);

        // Redirect to the departments page with a success message
        res.redirect('/principal/departments?message=Department removed successfully');
    } catch (error) {
        console.error('Error removing department:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.get("/createAppraisal", async (req, res) => {
    try {
        const instituteId = req.user.institution_id;
        const [departments] = await facultyDb.query(
            'SELECT * FROM department_master WHERE institution_id = ? AND status="active"',
            [instituteId]
        );
        res.render('./principal/createAppraisal', { departments });
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).send('Internal Server Error');
    }
})

router.get("/sessionActivate", async (req, res) => {
    const institute_id = req.user.institution_id;
    try {
        // Query to get all appraisal cycles for a specific institution
        const [appraisals] = await facultyDb.query(`
    SELECT DISTINCT 
        am.appraisal_id, 
        am.appraisal_cycle_name, 
        am.start_date, 
        am.end_date ,am.status
    FROM appraisal_master am
    JOIN appraisal_departments ad ON am.appraisal_id = ad.appraisal_id
    WHERE ad.institution_id = ?
`, [institute_id]);

    
    
        // Check if no appraisal cycles are found for the given institution
        if (appraisals.length === 0) {
          return res.status(404).send('No appraisal cycles found for this institution.');
        }
    
        // Render the appraisal table page and pass the appraisals data
        res.render('./principal/ShowAppraisalCycle', { appraisals });
      } catch (error) {
        console.error('Error fetching appraisal data:', error);
        res.status(500).send('Internal Server Error');
      }
})

router.post("/appraisal/updateStatus", async (req, res) => {
    const { appraisalId, grades } = req.body;
    try {
        const connection = await facultyDb.getConnection();

        await connection.beginTransaction();

        try {
            await connection.query('UPDATE appraisal_master SET status = ? WHERE appraisal_id = ?', ['active', appraisalId]);

            for (const grade of grades) {
                await connection.query('INSERT INTO grade_master (grade_id, appraisal_id, grade_title, min_marks, max_marks) VALUES (?, ?, ?, ?, ?)', [grade.title, appraisalId, grade.title, grade.min, grade.max]);
            }

            await connection.commit();
            res.json({ message: 'Appraisal status updated and grades inserted successfully' });
        } catch (error) {
            await connection.rollback();
            console.error('Error:', error);
            res.status(500).send('Internal Server Error');
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});
router.get("/grade", async (req, res) => {
    try {
        // Get appraisal_id and total_marks from the request query parameters
        const { appraisal_id, total_marks } = req.query;

        // Pass appraisal_id and total_marks to the grade view
        res.render("./principal/grade", { appraisal_id, total_marks });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
});
router.get("/criteriaSelection/:appraisalId", async (req, res) => {
    try {
        const instituteId = req.user.institution_id;
        const appraisalId = req.params.appraisalId;  // Access the appraisalId parameter

        const [criteria] = await facultyDb.query(
            'SELECT * FROM criteria_master where type ="self"; '
        );

        res.render('./principal/criteriaSelection', { criteria, appraisalId });  // Pass appraisalId to the view
        
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).send('Internal Server Error');
    }
});


router.get('/parameterTable', async (req, res) => {
    const appraisalId = req.query.appraisal_id;
    const selectedCriteriaIds = req.query.criteria; // Get the selected criteria from the query
console.log(selectedCriteriaIds,appraisalId)
console.log(req.query)
    if (!Array.isArray(selectedCriteriaIds)) {
        return res.status(400).send({ message: 'No criteria selected.' });
    }

    try {
        // Fetch criteria details including parameters from the database
        const criteria = await getCriteriaWithParameters(selectedCriteriaIds);
        console.log(criteria)
        // Render the parameter table page with the criteria and appraisalId
        res.render('./principal/parameterTable', {
            criteria,
            appraisalId,
            message: `Selected ${selectedCriteriaIds.length} criteria.`
        });
    } catch (error) {
        console.error('Error fetching criteria:', error);
        res.status(500).send({ message: 'Internal server error.' });
    }
});




// Endpoint to add a new parameter
router.post('/add-parameter', (req, res) => {
    const { criteria_id, parameter_description, parameter_max_marks, parameter_description_type } = req.body;

    if (!criteria_id || !parameter_description || !parameter_max_marks || !parameter_description_type) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    const insertQuery = `INSERT INTO c_parameter_master (criteria_id, parameter_description, parameter_max_marks, parameter_description_type) VALUES (?, ?, ?, ?)`;
    facultyDb.query(insertQuery, [criteria_id, parameter_description, parameter_max_marks, parameter_description_type], (err, result) => {
        if (err) {
            console.error('Error inserting new parameter:', err);
            return res.status(500).json({ error: 'Database error inserting parameter.' });
        }

        res.json({ message: 'Parameter added successfully.', parameter_id: result.insertId });
    });
});




router.get("/criteriaMarks/:appraisal_id", async (req, res) => {
    const appraisal_id = req.params.appraisal_id;

    try {
        // SQL query to fetch criteria data based on the appraisal_id
        const [criteriaData] = await facultyDb.query(`
            SELECT 
                cm.criteria_id AS criteria_name,
                COUNT(acp.c_parameter_id) AS total_parameters,
                SUM(acp.total_marks) AS total_marks
            FROM 
                criteria_master cm
            LEFT JOIN 
                apprisal_criteria_parameter_master acp ON cm.criteria_id = acp.criteria_id
            WHERE 
                acp.appraisal_id = ?
            GROUP BY 
                cm.criteria_id
        `, [appraisal_id]);

        // Render the criteriaMarks EJS template with the fetched criteriaData
        res.render("./principal/criteriaMarks", { criteriaData ,appraisal_id});
    } catch (error) {
        console.error('Error fetching criteria data:', error);
        res.status(500).send('Server Error');
    }
});

const insertIntoAppraisalDepartments = async (appraisalId, departmentId, institutionId) => {
    try {
        await facultyDb.query(`
            INSERT INTO appraisal_departments (appraisal_id, department_id, institution_id, status)
            VALUES (?, ?, ?, 'active')`,
            [appraisalId, departmentId, institutionId]
        );
    } catch (error) {
        if (error.code !== 'ER_DUP_ENTRY') {
            throw error;  // Re-throw any other errors
        }
        console.log(`Duplicate entry for department ${departmentId}, skipping...`);
    }
}

router.post("/appraisal/create", async (req, res, next) => {
    const { cycle_name, department_name, start_date, end_date } = req.body;
    const institutionId = req.user.institution_id;
    const userId = req.user.user_id;

    try {
        const [user_id_query] = await facultyDb.query(`SELECT user_id FROM user_master where user_type_id = ?`, [userId]);
        const user_id = user_id_query[0].user_id;

        const [appraisalResult] = await facultyDb.query(
            `INSERT INTO appraisal_master (appraisal_cycle_name, user_id, status,start_date,end_date)
             VALUES (?, ?,'inactive', ?,?)`,
            [cycle_name, user_id,start_date,end_date]
        );

        if (appraisalResult.affectedRows > 0) {
            const [appraisal] = await facultyDb.query('SELECT appraisal_id FROM appraisal_master WHERE id = LAST_INSERT_ID()');
            const appraisalId = appraisal[0].appraisal_id;

            if (department_name === 'all') {
                const [departments] = await facultyDb.query(
                    'SELECT dept_id FROM department_master WHERE institution_id = ?',
                    [institutionId]
                );

                for (const department of departments) {
                    const [existingEntry] = await facultyDb.query(`
                        SELECT * FROM appraisal_departments WHERE appraisal_id = ? AND department_id = ? AND institution_id = ?
                    `, [appraisalId, department.dept_id, institutionId]);

                    if (existingEntry.length === 0) {
                        await insertIntoAppraisalDepartments(appraisalId, department.dept_id, institutionId);
                    }
                }
                res.json({ success: true, appraisalId: appraisalId });
               
            } else {
                const [departmentResult] = await facultyDb.query(`
                    SELECT dept_id FROM department_master WHERE department_name = ? AND institution_id = ?
                `, [department_name, institutionId]);

                if (departmentResult.length === 0) {
                    return res.json({ success: false, message: 'Department not found' });
                }

                const departmentId = departmentResult[0].dept_id;
                await insertIntoAppraisalDepartments(appraisalId, departmentId, institutionId);

                res.json({ success: true, appraisalId: appraisalId });
            }
        }
    } catch (error) {
        console.error('Error creating appraisal cycle:', error);
        next(error);  // Pass the error to the error handling middleware
    }
});

router.get('/parameterReview', async (req, res) => {
    try {
        const appraisalId = req.query.appraisal_id;  // Fetch appraisal ID from query
        const selectedCriteria = req.query.criteria; // This will be an array of selected criteria
        const instituteId = req.user.institution_id;
        console.log(selectedCriteria)
        // Check if criteria are selected
        if (!selectedCriteria || selectedCriteria.length === 0) {
            return res.status(400).json({
                message: 'No criteria selected. Please select at least one criterion.'
            });
        }

        // Fetch criteria details
        const criteriaQuery = `SELECT criteria_id, criteria_description FROM criteria_master WHERE criteria_id IN (?)`;
        const [criteria] = await facultyDb.query(criteriaQuery, [selectedCriteria]);

        // Check if any criteria were found
        if (criteria.length === 0) {
            return res.status(404).json({
                message: 'No criteria found for the selected IDs.'
            });
        }

        // Convert criteria into a query string format
        const criteriaParams = criteria.map(criterion => `criteria[]=${criterion.criteria_id}`).join('&');

        // Redirect to /parameterTable route with appraisalId and criteria as query params
        res.redirect(`/Principal/parameterTable?appraisalId=${appraisalId}&${criteriaParams}`);
    } catch (error) {
        console.error('Error processing criteria selection:', error);
        res.status(500).json({
            message: 'Internal Server Error'
        });
    }
});







router.post('/addCriteria', async (req, res) => {
    const { criteria_description, parameter_description, total_marks } = req.body;

    try {
        // Insert new criteria into criteria_master table
        await facultyDb.query('INSERT INTO criteria_master (criteria_description, type) VALUES (?, "appraisal")', [criteria_description]);

        // Retrieve the criteria_id of the newly inserted criteria using a SELECT query
        const [criteriaResult] = await facultyDb.query('SELECT criteria_id FROM criteria_master WHERE criteria_description = ? ORDER BY criteria_id DESC LIMIT 1', [criteria_description]);
        
        // Check if the criteriaResult is valid and contains the criteria_id
        if (criteriaResult.length > 0) {
            const criteriaId = criteriaResult[0].criteria_id; // Get the first result's criteria_id



            // Send success response including the criteria ID
            return res.json({ message: 'Criteria and parameters added successfully!', criteriaId: criteriaId });
        } else {
            return res.status(500).json({ message: 'Failed to retrieve criteria ID.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred while adding criteria and parameters.' });
    }
});


router.post("/getParameters", async (req, res) => {
    try {
        const criteriaId = req.body.criteriaId; // Get the criteria ID from the request
        const parameters = await getParametersByCriteriaId(criteriaId); // Fetch parameters

        res.status(200).json({ parameters });
    } catch (error) {
        console.error('Error fetching parameters:', error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});
router.post('/addParameter', async (req, res) => {
    const { criteriaId, description, marks } = req.body;

    // Basic input validation
    if (!criteriaId || !description || typeof marks === 'undefined') {
        return res.status(400).json({ message: 'Missing or invalid fields: criteriaId, description, or marks.' });
    }

    try {
        const query = `
            INSERT INTO c_parameter_master (criteria_id, parameter_description, parameter_max_marks, status)
            VALUES (?, ?, ?, 'active')
        `;
        
        const result = await facultyDb.query(query, [criteriaId, description, marks]);

        // Get the ID of the newly inserted parameter
        const newParameterId = result.insertId; 
        
        // Prepare the new parameter object to return
        const newParameter = {
            parameter_id: newParameterId,
            criteria_id: criteriaId,
            parameter_description: description,
            parameter_max_marks: marks,
            status: 'active'
        };

        res.status(201).send({ message: 'Parameter added successfully', parameter: newParameter });
    } catch (error) {
        console.error('Error adding parameter:', error.message);
        res.status(500).json({ message: 'Internal Server Error', error: error.message });
    }
});




router.post('/submitParameters', async (req, res) => {
    console.log("Test");

    const { parameters } = req.body; // Destructure parameters from request body

    // Check if parameters are provided
    if (!parameters || parameters.length === 0) {
        return res.status(400).json({ message: 'No parameters provided.' });
    }

    // Populate appraisal_id for each parameter
    const parametersWithAppraisalId = parameters.map(param => ({
        criteria_id: param.criteria_id,
        c_parameter_id: param.c_parameter_id,
        appraisal_id: param.appraisal_id,
        total_marks: param.total_marks
    }));

    // Optionally remove duplicates
    const uniqueParameters = Array.from(new Set(parametersWithAppraisalId.map(param => JSON.stringify(param))))
                                  .map(param => JSON.parse(param));

    const connection = await facultyDb.getConnection(); // Get a connection from the pool

    try {
        await connection.beginTransaction(); // Start a transaction

        // Prepare an array to hold all the insert promises
        const insertPromises = uniqueParameters.map(param => {
            return connection.query(
                `INSERT INTO apprisal_criteria_parameter_master (criteria_id, c_parameter_id, appraisal_id, total_marks)
                 VALUES (?, ?, ?, ?)`,
                [param.criteria_id, param.c_parameter_id, param.appraisal_id, param.total_marks]
            );
        });

        await Promise.all(insertPromises); // Wait for all inserts to complete

        await connection.commit(); // Commit the transaction
        
        // Send a JSON response indicating success with the redirect URL
        res.json({ message: 'Parameters submitted successfully!', redirectUrl: `/principal/criteriaMarks/${parameters[0].appraisal_id}` });

    } catch (error) {
        await connection.rollback(); // Rollback the transaction in case of an error
        console.error('Error inserting parameters:', error);

        // Check if the error is a deadlock error
        if (error.code === 'ER_LOCK_DEADLOCK') {
            return res.status(409).json({ message: 'Deadlock occurred. Please try again.' });
        }
        
        return res.status(500).json({ message: 'Failed to add parameters.' });
    } finally {
        connection.release(); // Release the connection back to the pool
    }
});













router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/principal/login')});

export default router;