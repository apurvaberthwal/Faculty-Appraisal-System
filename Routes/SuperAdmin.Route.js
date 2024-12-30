import bcrypt from 'bcryptjs';
import express from 'express';
import jwt from 'jsonwebtoken';
import facultyDb from '../faculty.db.js';

const router = express.Router();
router.get("/login",async (req, res) => {
    res.render("./superAdmin/login.ejs");
})
router.use((req, res, next) => {
    if (req.cookies.token) {
        try {
            const user = jwt.verify(req.cookies.adminToken, process.env.JWT_SECRET);
            req.user = user;
            console.log('Decoded JWT:', user); // Log the decoded JWT payload
            console.log('User ID:', user.user_id); // Log the user ID specifically
            res.locals.loggedIn = user.loggedIn; // Set a local variable
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

router.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    try {
        const result = await facultyDb.query(
            'SELECT * FROM user_type_master WHERE user_name = ? AND user_type_type = "superAdmin"',
            [username]
        );
        const user = result[0];

        if (user.length > 0) {
            const user_id = user[0].user_type_id;
            const role = 'superAdmin'; // Hardcoding role for superAdmin
            const status = user[0].status; // Assuming `status` is a field in `user_type_master`
            const hashedPassword = user[0].password; // Assuming `password` is a field in `user_type_master`

            const passwordMatch = await bcrypt.compare(password, hashedPassword);

            // Check if the user status is inactive
            if (status === 'inactive') {
                res.status(401).send('Account is inactive');
            } else if (!passwordMatch) {
                res.status(401).send('Invalid username or password');
            } else {
                const token = jwt.sign({ user_id, role }, process.env.JWT_SECRET, { expiresIn: '2h' });
                res.cookie('adminToken', token, { httpOnly: true });
                res.redirect('/superAdmin/dashboard');
            }
        } else {
            res.status(401).send('Invalid username or password');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});


router.get('/pending-requests', async (req, res) => {
    try {
        const result = await facultyDb.query("SELECT COUNT(*) as count FROM user_type_master WHERE status = 'inactive' AND user_type_type = 'admin'");
      //  console.log(result)
        const pendingRequests = result[0][0].count;
      //  console.log(pendingRequests)
        res.json({ pendingRequests });
    } catch (error) {
        console.error('Error fetching pending requests:', error);
        res.json({ pendingRequests: 0 });
    }
});
router.get("/dashboard",async (req, res) => {
    res.render("./superAdmin/dashboard");
})
// Middleware to fetch pending approvals count for the navbar

router.get("/createInstitute",async (req, res) => {
    res.render("./superAdmin/add_institute");
})
router.get("/createDepartment",async (req, res)=> {
    res.render("./superAdmin/add_department");
});    

// GET route to display pending approvals with success and error messages
router.get('/approvals', async (req, res) => {
    const { successMsg, errorMsg } = req.query;

    try {
        const query = `SELECT utm.user_type_id, utm.user_name, um.first_name, um.last_name, im.institution_name, utm.timestamp
                        FROM user_type_master utm
                        JOIN user_master um ON utm.user_type_id = um.user_type_id
                        JOIN institution_master im ON um.institution_id = im.institution_id
                        WHERE utm.user_type_type = 'admin' AND utm.status = 'inactive'`;
        const [rows] = await facultyDb.execute(query);
        
        res.render('./superadmin/approvals', { principals: rows, successMsg, errorMsg });
    } catch (error) {
        console.error('Error retrieving pending approvals:', error);
        res.status(500).send('An error occurred while fetching data.');
    }
});

// POST route to approve principal
router.post('/approve/:user_type_id', async (req, res) => {
    const { user_type_id } = req.params;

    try {
        const updateQuery = `UPDATE user_type_master SET status = 'active', timestamp = CURRENT_TIMESTAMP WHERE user_type_id = ?`;
        await facultyDb.execute(updateQuery, [user_type_id]);
        const updateQuery2 = `UPDATE user_master SET status = 'active', timestamp = CURRENT_TIMESTAMP WHERE user_type_id = ?`;
        await facultyDb.execute(updateQuery2, [user_type_id]);


        res.redirect('/superadmin/approvals?successMsg=Principal account approved successfully.');
    } catch (error) {
        console.error('Error updating principal status:', error);
        res.redirect('/superadmin/approvals?errorMsg=Failed to approve principal.');
    }
});

export default router;