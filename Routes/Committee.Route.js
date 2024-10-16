import bcrypt from 'bcryptjs';
import express from 'express';
import jwt from 'jsonwebtoken';
import facultyDb from '../faculty.db.js';
import { authorizeRole, jwtMiddleware } from '../service.js';
const router = express.Router();
router.use(jwtMiddleware);
router.get('/login', (req, res) => {
    console.log("Committee");
    res.render("./Committee/login");
});
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
            res.locals.user=user;
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











router.post('/login', async (req, res) => {
    
    const username = req.body.uname;
    const password = req.body.password;
    console.log("Committee", username, password);

    try {
        const result = await facultyDb.query(
            'SELECT * FROM user_type_master WHERE user_name = ?  AND user_type_type= "committee"',
            [username]
        );
        const user = result[0]; // Access the actual user data
        console.log('User from DB:',user);
        const hashedPassword = user[0].password;
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        if (user.length > 0 && hashedPassword) {
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
            res.redirect('/Committee/home');
        } else {
            res.render("./Committee/login", { error: "Invalid username or password." });
        }
    } catch (error) {
        console.error(error);
        res.render("./committee/login", { error: "An error occurred. Please try again." });
    }
});




router.get("/home", async (req, res) => {

    res.render("./Committee/home");
})





router.use(authorizeRole('committee'));

router.get("/reports/:appraisal_id", async (req, res) => {
    const institution_id = req.user.institution_id;
    const appraisal_id = req.params.appraisal_id; // Get appraisal_id from URL parameter
    console.log("institution_id", institution_id);
    console.log("appraisal_id", appraisal_id);

    try {
        const query = `
        SELECT
    u.user_id,
    u.email_id,
    u.emp_id,
    CONCAT(u.first_name, ' ', u.last_name) AS name,
    d.department_name,
    COUNT(DISTINCT cp.criteria_id) AS criteria_applied,
    total_criteria.total AS total_criteria,
    CASE
        WHEN COUNT(DISTINCT cp.criteria_id) = total_criteria.total THEN 'Fully filled'
        WHEN COUNT(DISTINCT cp.criteria_id) > 0 THEN 'Partially filled'
        ELSE 'Not filled'
    END AS appraisal_status
FROM
    user_master u
JOIN department_master d ON u.dept_id = d.dept_id
LEFT JOIN self_appraisal_score_master sasm ON u.user_id = sasm.user_id
    AND sasm.status = 'active' AND sasm.appraisal_id = ? -- Placeholder for appraisal_id
LEFT JOIN c_parameter_master cp ON sasm.c_parameter_id = cp.c_parameter_id
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
    u.institution_id = ? 
GROUP BY
    u.user_id, u.emp_id, u.first_name, u.last_name, d.department_name, u.email_id, total_criteria.total;

    `;
    
    const [rows] = await facultyDb.query(query, [appraisal_id, appraisal_id,institution_id]);
    // Pass appraisal_id as parameter
        if (rows.length === 0) {
            res.render("./Committee/report", { employees: [], error: "No data found.",appraisal_id:appraisal_id });
            return;
        }
        console.log(rows);

        res.render("./Committee/report", { employees: rows ,appraisal_id:appraisal_id});
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});

router.get('/reports/:appraisal_id/:user_id', async (req, res) => {
    console.log("criteria-status");
    const successMsg = req.query.message || "";
    const userId = req.params.user_id;  // Get user ID from route parameters
    const appraisal_id = req.params.appraisal_id; // Get appraisal ID from route parameters
    console.log(userId,appraisal_id)
    if (!userId) {
        console.error('User ID is missing in the request.');
        return res.status(400).send('User ID is required.');
    }

    try {
        // SQL query to get criteria status and actions including review status
        const query2 = `
            SELECT 
                c.criteria_id AS 'Criteria Number',
                c.criteria_description AS 'Criteria Name',
                CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM self_appraisal_score_master sas
                        JOIN apprisal_criteria_parameter_master acp ON sas.c_parameter_id = acp.c_parameter_id
                        WHERE sas.user_id = ? 
                        AND sas.record_id IS NOT NULL
                        AND sas.appraisal_id = ?
                        AND acp.criteria_id = c.criteria_id
                    ) THEN 'Applied'
                    ELSE 'Not Applied'
                END AS 'Self-Appraisal Status',
                CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM committee_master cm
                        JOIN apprisal_criteria_parameter_master acp ON cm.c_parameter_id = acp.c_parameter_id
                        WHERE cm.user_id_employee = ? 
                        AND cm.status = 'active'
                        AND acp.criteria_id = c.criteria_id
                        AND cm.appraisal_id = ?
                    ) THEN 'Reviewed'
                    ELSE 'Not Reviewed'
                END AS 'Committee Status'
            FROM criteria_master c
            LEFT JOIN apprisal_criteria_parameter_master acp
                ON c.criteria_id = acp.criteria_id
            LEFT JOIN appraisal_master am
                ON acp.appraisal_id = am.appraisal_id
            WHERE c.status = 'active'
              AND am.status = 'active'
              AND am.appraisal_id = ?
            GROUP BY c.criteria_id, c.criteria_description
            ORDER BY c.criteria_id;
        `;

        // Execute the query with the user ID and appraisal ID
        const results2 = await facultyDb.query(query2, [userId, appraisal_id, userId, appraisal_id, appraisal_id]);
        console.log('Criteria Results:', results2[0]);

        if (results2.length === 0) {
            console.log('No criteria data found');
        }

        // Render the results in the view
        res.render('./Committee/criteria-status', { userId, data: results2, successMsg ,appraisal_id:appraisal_id});

    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});



router.post("/criteria-Status/review", async (req, res) => {
    const userId = req.body.user_id;
    const criteriaId = req.body.criteria_id;
    console.log("criteriaId", criteriaId);
    console.log("userId", userId);
    
    try {
        // Assuming you have an appraisal ID available (you can get it from your request body or session)
        const appraisalId = req.body.appraisal_id; // Make sure this ID is sent from the form
        console.log("appraisalId", appraisalId);
        // Fetch criteria and parameters only for applied parameters related to the appraisal ID
        const criteriaQuery = `
            SELECT c.criteria_description AS 'criteriaName', cp.*, 
                   sas.marks_by_emp, COALESCE(cm.comm_score, 'Pending') AS committeeScore
            FROM criteria_master c
            JOIN c_parameter_master cp ON c.criteria_id = cp.criteria_id
            LEFT JOIN self_appraisal_score_master sas ON cp.c_parameter_id = sas.c_parameter_id 
                AND sas.user_id = ? AND sas.appraisal_id = ?
            LEFT JOIN committee_master cm ON sas.record_id = cm.record_id
            WHERE c.criteria_id = ? AND sas.record_id IS NOT NULL
        `;
        const [parameters] = await facultyDb.query(criteriaQuery, [userId, appraisalId, criteriaId]);
        console.log(parameters);
        // Fetch documents for applied parameters only
        const documentQuery = `
            SELECT d.document_id, d.doc_link AS document_path, d.c_parameter_id
            FROM document_master d
            JOIN c_parameter_master cp ON d.c_parameter_id = cp.c_parameter_id
            LEFT JOIN self_appraisal_score_master sas ON cp.c_parameter_id = sas.c_parameter_id 
                AND sas.user_id = ? AND sas.appraisal_id = ?
            WHERE cp.criteria_id = ? AND d.user_id = ? AND sas.record_id IS NOT NULL
        `;
        const [documents] = await facultyDb.query(documentQuery, [userId, appraisalId, criteriaId, userId]);

        // Render EJS template
        res.render('Committee/review', { parameters, documents, criteriaId, criteriaName: parameters[0]?.criteriaName || 'No Criteria', userId });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

router.post("/save-committee-scores", async (req, res) => {
        const { criteria_id, user_id, ...committeeScores } = req.body;
        console.log(req.user.user_id);
        let commid;  // Define commid here
    
        try {
            const committeeQuery = 
              `  SELECT user_id
                FROM user_master
                WHERE user_type_id = ?`
            ;
            const committeeResult = await facultyDb.query(committeeQuery, [req.user.user_id]);
            console.log("committeeResult", committeeResult);  // Add this line
        
            if (committeeResult.length > 0) {  // Add this check
                commid = committeeResult[0][0].user_id;
                console.log("committee",commid);
            } else {
                console.log("No results from committee query");
            }
        } catch (err) {
            console.error('Error fetching committee members:', err);
            return res.status(500).send('Error retrieving committee members.');
        }    
    
        // Input validation
        if (!criteria_id || !user_id) {
            console.error('Invalid input: criteria_id or user_id is missing');
            return res.status(400).send('Invalid input: criteria_id and user_id are required.');
        }
    
        const scores = [];
    
        console.log('Received committee scores:', committeeScores);
    
        // Extract all committee scores from the request body
        for (const [key, value] of Object.entries(committeeScores)) {
            if (key.startsWith('committee_score_')) {
                const c_parameter_id = key.replace('committee_score_', '');
                const score = parseInt(value, 10);
    
                if (isNaN(score) || score < 0) {
                    console.error(`Invalid score value for parameter ${c_parameter_id}: ${value}`);
                    return res.status(400).send(`Invalid score value for parameter ${c_parameter_id}.`);
                }
    
                // Retrieve the record_id for the given user_id, c_parameter_id, and criteria_id
                let record_id;
                try {
                    const recordQuery = `
                        SELECT record_id
                        FROM self_appraisal_score_master
                        WHERE user_id = ? AND c_parameter_id = ? AND status = 'active'
                    `;
                    const [recordResult] = await facultyDb.query(recordQuery, [user_id, c_parameter_id, criteria_id]);
    
                    console.log(`Record query result for user_id: ${user_id}, c_parameter_id: ${c_parameter_id}, criteria_id: ${criteria_id}:`, recordResult);
    
                    if (recordResult.length === 0) {
                        console.error(`Record ID not found for user_id: ${user_id}, c_parameter_id: ${c_parameter_id}, criteria_id: ${criteria_id}`);
                        continue;  // Skip this parameter
                    }
                    record_id = recordResult[0].record_id;
                    console.log(`Retrieved record_id for parameter ${c_parameter_id}: ${record_id}`);
                } catch (err) {
                    console.error('Error fetching record ID:', err);
                    return res.status(500).send('Error retrieving record ID.');
                }
    
                // Print parameter_id and committee_score
                console.log(`parameter_id: ${c_parameter_id}, committee_score: ${score}`);
    
                // Check if the record already exists
                try {
                    const checkQuery = `
                        SELECT COUNT(*) AS count
                        FROM committee_master
                        WHERE record_id = ? AND user_id_committee = ?
                    `;
                    const [checkResult] = await facultyDb.query(checkQuery, [record_id, user_id]);
    
                    if (checkResult[0].count === 0) {
                        // Prepare values for insertion if record does not exist
                        scores.push([
                           commid ,        // user_id_committee
                            user_id,        // user_id_employee
                            record_id,      // record_id
                            c_parameter_id, // c_parameter_id
                            score           // comm_score
                        ]);
                    } else {
                        console.log(`Record already exists for record_id: ${record_id}`);
                    }
                } catch (err) {
                    console.error('Error checking for existing record:', err);
                    return res.status(500).send('Error checking for existing records.');
                }
            }
        }
    
        console.log('Prepared scores for insertion:', scores);
    
        if (scores.length === 0) {
            console.error('No valid committee scores provided.');
            return res.status(400).send('No valid committee scores provided.');
        }
    
        // Insert scores
        try {
            const insertQuery = `
                INSERT INTO committee_master (user_id_committee, user_id_employee, record_id, c_parameter_id, comm_score)
                VALUES (?)
            `;
          
            for (const score of scores) {
                try {
                    const [insertResult] = await facultyDb.query(insertQuery, [score]);
                    console.log('Insert result:', insertResult);
                } catch (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        console.log('Duplicate entry, skipping:', score);
                    } else {
                        throw err;  // Rethrow the error if it's not a duplicate entry error
                    }
                }
            }
    
            // Redirect to criteria status with userId and success message
            res.redirect(`/committee/criteria-Status?user_id=${user_id}&message=Successfully%20added%20review`);
        } catch (err) {
            console.error('Error inserting committee scores:', err);
            res.status(500).send('Error saving committee scores.');
        }
    });
    

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/committee/login')});




router.get('/addCriteria', (req, res) => {

    
    res.render('./committee/addCriteria',{success :"",errors:""});


})
router.post('/addCriteria', async(req, res) => {
    const {  criteria_description, max_marks,  } = req.body;
   
    try {
        // Insert data into the database
        await facultyDb.query('INSERT INTO criteria_master ( criteria_description, max_marks) VALUES (?, ?)', [ criteria_description, max_marks]);

        // Send success message and redirect
        res.render('./committee/addCriteria', { success : 'Criteria added successfully!',errors:"" });
    } catch (error) {
        // Handle database errors
        console.error('Database error:', error);
        res.render('./committee/addCriteria', { errors: ['An error occurred while adding the criteria. Please try again.'], success: "" });
    }

})








router.get("/addParams", async (req, res) => {
        try {
            const data = await facultyDb.query('SELECT criteria_description FROM criteria_master');
            if (!data) {
                console.log('No data returned from the query');
                res.status(500).send('No data returned from the query');
                return;
            }
            res.render('./committee/criteriaSelect', { data: data[0], successMessage:"", errorMessage:"" });
        } catch (error) {
            console.error('Error executing query', error);
            res.status(500).send('Error executing query');
        }
    });
    
router.post("/addParams", async (req, res) => {
    const criteria_id = req.body.criteria_id;
    const parameter = req.body.parameter_description;
    const totalMarks = req.body.parameter_max_marks;
    const paramType = req.body.parameter_description_type; // 'required' or 'optional'
    console.log(criteria_id + ": " + parameter + " " + totalMarks + " " + paramType);
    
    const data1 = await facultyDb.query('SELECT criteria_description FROM criteria_master');
     // Validate inputs
     if (!criteria_id || !parameter || (paramType === 'required' && (!totalMarks || isNaN(totalMarks) || totalMarks <= 0))) {
        return res.render('./committee/criteriaSelect', { 
            errorMessage: 'All fields are required and Total Marks must be a positive number if the parameter is required!', 
            successMessage: "", 
            data: data1[0]
        });
    }
    
    try {

            
            await facultyDb.query(
                'INSERT INTO c_parameter_master (criteria_id, parameter_description, parameter_max_marks, parameter_description_type) VALUES (?, ?, ?, ?)',
                [criteria_id, parameter, totalMarks || null, paramType]
            );    
            res.redirect(`/committee/criteria/${criteria_id}/parameters?message=parameter added successfully`);    
           
        } catch (error) {
            console.error('Error executing query', error);
            res.render('./committee/criteriaSelect', {successMessage:"", errorMessage: 'Error inserting data. Please try again.',  data: data1[0] });
        }
    });
    



// Get all criteria
router.get('/criteria', async (req, res) => {
    try {
        const [criteria] = await facultyDb.query('SELECT * FROM criteria_master WHERE status = "active"');
        res.render('./committee/criteria', {
            criteria: criteria,
            message: req.query.message || null
        });
    } catch (error) {
        console.error('Error fetching criteria:', error);
        res.status(500).send('Internal Server Error');
    }
});
router.post('/criteria/remove', async (req, res) => {
    const { criteria_id } = req.body;
    try {
        await facultyDb.query('UPDATE criteria_master SET status = "inactive" WHERE criteria_id = ?', [criteria_id]);
        res.redirect('/committee/criteria?message=Criteria removed successfully');
    } catch (error) {
        console.error('Error removing criteria:', error);
        res.status(500).send('Internal Server Error');
    }
})

// Get parameters for a specific criteria
router.get('/criteria/:criteria_id/parameters', async (req, res) => {
    const { criteria_id } = req.params;
    try {
        const [parameters] = await facultyDb.query('SELECT * FROM c_parameter_master WHERE criteria_id = ? AND status = "active"', [criteria_id]);
        res.render('./committee/parameters', {
            criteria_id: criteria_id,
            parameters: parameters,
            message: req.query.message || null
        });
    } catch (error) {
        console.error('Error fetching parameters:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Add new parameter
router.post('/parameters/add', async (req, res) => {
    const { parameter_description_type, parameter_description, parameter_max_marks, criteria_id } = req.body;
    try {
        await facultyDb.query('INSERT INTO c_parameter_master (parameter_description_type, parameter_description, parameter_max_marks, criteria_id) VALUES (?, ?, ?, ?)', [parameter_description_type, parameter_description, parameter_max_marks, criteria_id]);
        res.redirect(`/committee/criteria/${criteria_id}/parameters?message=Parameter added successfully`);
    } catch (error) {
        console.error('Error adding parameter:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Remove parameter
router.post('/parameters/remove', async (req, res) => {
    const { c_parameter_id, criteria_id } = req.body;
    try {
        await facultyDb.query('UPDATE c_parameter_master SET status = "inactive" WHERE c_parameter_id = ?', [c_parameter_id]);
        res.redirect(`/committee/criteria/${criteria_id}/parameters?message=Parameter removed successfully`);
    } catch (error) {
        console.error('Error removing parameter:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.get("/sessionActivate", async (req, res) => {
    
    const committeeQuery = 
              `  SELECT user_id
                FROM user_master
                WHERE user_type_id = ?`
            ;
            const user_id = await facultyDb.query(committeeQuery, [req.user.user_id]);
            console.log(user_id);
    const institute_id = req.user.institution_id;
    try {
        // Query to get all appraisal cycles for a specific institution
        const [appraisals] = await facultyDb.query(`
        SELECT DISTINCT 
        am.appraisal_id, 
        am.appraisal_cycle_name, 
        am.start_date, 
        am.end_date, 
        am.status
    FROM appraisal_master am
    JOIN appraisal_departments ad ON am.appraisal_id = ad.appraisal_id
    JOIN committee_member_master cmm ON am.appraisal_id = cmm.appraisal_id
    WHERE ad.institution_id = "INS8"
    AND cmm.user_id = "USR1"
    AND cmm.status = 'active';
    
`, [user_id[0].user_id,institute_id]);

    
    
        // Check if no appraisal cycles are found for the given institution
        if (appraisals.length === 0) {
          return res.status(404).send('No appraisal cycles found for this institution.');
        }
    
        // Render the appraisal table page and pass the appraisals data
        res.render('./Committee/committeeReport', { appraisals });
      } catch (error) {
        console.error('Error fetching appraisal data:', error);
        res.status(500).send('Internal Server Error');
      }
})















export default router;




