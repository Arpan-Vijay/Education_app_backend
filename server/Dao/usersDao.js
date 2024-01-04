const connectionProvider = require("../mySqlConnectionStringProvider.js");
const jwt = require("jsonwebtoken");
const XLSX = require("xlsx");
const fs = require("fs");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const bcrypt = require("bcrypt");
const { promisify } = require("util");
const nodemailer = require("nodemailer");
const { query } = require("express");
const sendEmail = require("./emailSender");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
// const AWS = require('aws-sdk');

const pool = require("../mySqlConnectionString.js"); // Assuming you have a separate file for creating a connection pool

const unlinkAsync = promisify(fs.unlink);

// const unlinkAsync = promisify(fs.unlink);

exports.uploadOrgIcon = async function (req, res) {
  const path = req.file.path;
  const fileContent = fs.readFileSync(path);
  const params = {
    Bucket: "embed-app-bucket",
    Key: "OrgIcon-" + req.params.orgId,
    Body: fileContent,
  };

  const command = new PutObjectCommand(params);

  try {
    const response = await s3Client.send(command);
    console.log("Image uploaded successfully. Location:", response);
    await unlinkAsync(path);
    res.status(200).send({ message: "uploaded successfully" });
  } catch (error) {
    console.error("Error uploading image:", error);
  }
};

exports.uploadProfileImage = async function (req, res) {
  const path = req.file.path;
  const fileContent = fs.readFileSync(path);
  const params = {
    Bucket: "embed-app-bucket",
    Key: "Image-" + req.body.userDetails.adminId,
    Body: fileContent,
  };

  const command = new PutObjectCommand(params);

  try {
    const response = await s3Client.send(command);
    console.log("Image uploaded successfully. Location:", response);
    await unlinkAsync(path);
    res.status(200).send({ message: "uploaded successfully" });
  } catch (error) {
    console.error("Error uploading image:", error);
  }
};

exports.retrieveOrgIcon = async function (req, res) {
  const params = {
    Bucket: "embed-app-bucket",
    Key: "OrgIcon-" + req.params.orgId,
    ResponseContentType: "image/jpeg",
  };

  const command = new GetObjectCommand(params);

  try {
    const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
    console.log("Image retrieved successfully.", url);
    res.status(200).send({ dataUrl: url });
  } catch (error) {
    console.error("Error retrieving image:", error);
  }
};

exports.retrieveProfileImage = async function (req, res) {
  const params = {
    Bucket: "embed-app-bucket",
    Key: "Image-" + req.body.userDetails.adminId,
    ResponseContentType: "image/jpeg",
  };

  const command = new GetObjectCommand(params);

  try {
    // const response = await s3Client.send(command);
    // const imageFile = response.Body;
    const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
    console.log("Image retrieved successfully.", url);
    res.status(200).send({ dataUrl: url });
  } catch (error) {
    console.error("Error retrieving image:", error);
  }
};

exports.deleteProfileImage = async function (req, res) {
  const deleteParams = {
    Bucket: "embed-app-bucket",
    Key: "testImage.jpg",
  };

  const deleteCommand = new DeleteObjectCommand(deleteParams);

  try {
    const data = await s3Client.send(deleteCommand);
    console.log("Object deleted successfully");
    res.status(200).send({ message: "uploaded successfully" });
  } catch (error) {
    console.error("Error deleting object:", error);
  }
};

// ------------------------ Working Code ---------------------------------------

exports.adminLogin = function (request, response) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  const selectQuery = "SELECT * FROM admin_info WHERE email=?";
  const selectQueryPayload = [request.body.email];

  console.log("email:", request.body.email);
  console.log("password:", request.body.password);

  connection.query(
    selectQuery,
    selectQueryPayload,
    function (err, rows, fields) {
      if (err) {
        console.log("ERROR", err);
        response.status(500).send({ error: err });
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
        return;
      }

      console.log("Rows from the Database:", rows);

      if (rows.length === 1) {
        const storedPassword = rows[0].password;

        // Check if the entered password matches the stored password
        if (request.body.password === storedPassword) {
          // Password matches, proceed with authentication
          proceedWithAuthentication(response, rows[0]);
        } else {
          // Passwords do not match
          console.log("Invalid password");
          response.status(401).send("Invalid credentials");
          connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
            connection
          );
        }
      } else if (rows.length === 0) {
        console.log("Admin not found");
        response.status(404).send("Admin not found");
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
      } else {
        console.log("Unexpected number of rows:", rows.length);
        response.status(500).send("Internal Server Error");
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
      }
    }
  );
};

exports.userLogin = function (request, response) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  const selectQuery = "SELECT * FROM login WHERE sap_id=?";
  const selectQueryPayload = [request.body.sap_id];

  console.log("sap_id:", request.body.sap_id);
  console.log("password:", request.body.password);

  connection.query(
    selectQuery,
    selectQueryPayload,
    function (err, rows, fields) {
      if (err) {
        console.log("ERROR", err);
        response.status(500).send({ error: err });
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
        return;
      }

      console.log("Rows from the Database:", rows);

      if (rows.length === 1) {
        const storedPassword = rows[0].password;

        // Check if the entered password matches the stored password
        if (
          !rows[0].is_password_hashed &&
          request.body.password === storedPassword
        ) {
          // Password matches the original numeric password, proceed with authentication
          proceedWithAuthentication(response, rows[0]);
        } else if (bcrypt.compareSync(request.body.password, storedPassword)) {
          // Password matches the hashed password, proceed with authentication
          proceedWithAuthentication(response, rows[0]);
        } else {
          // Passwords do not match
          console.log("Invalid password");
          response.status(401).send("Invalid credentials");
          connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
            connection
          );
        }
      } else if (rows.length === 0) {
        console.log("User not found");
        response.status(404).send("User not found");
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
      } else {
        console.log("Unexpected number of rows:", rows.length);
        response.status(500).send("Internal Server Error");
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );
      }
    }
  );
};

function proceedWithAuthentication(response, user) {
  // Continue with authentication logic

  // Generate JWT token
  const resToSend = {
    user_id: user.user_id,
    sap_id: user.sap_id,
    school_id: user.school_id,
    school_name: user.school_name,
    first_name: user.first_name,
    last_name: user.last_name,
    middle_name: user.middle_name,
    email: user.email,
    role: user.role,
    birthdate: user.birthdate,
    father_name: user.father_name,
    mother_name: user.mother_name,
    aadhar_card: user.aadhar_card,
    pan_card: user.pan_card,
    contact_number: user.contact_number,
    alternative_contact_number: user.alternative_contact_number,
    permanent_address: user.permanent_address,
    communication_address: user.communication_address,
    city: user.city,
    state: user.state,
  };

  // Assuming 'token' is the JWT token
  const token = jwt.sign(resToSend, process.env.SECRET_KEY, {
    expiresIn: "50m",
  });

  const responsePayload = {
    success: true,
    message: "Authentication Successful",
    token: token,
  };

  response.json(responsePayload);
}

// Function to check if an email exists in the database
exports.checkEmailExists = async function (email) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  return new Promise((resolve, reject) => {
    const query = "SELECT COUNT(user_id) AS count FROM login WHERE email = ?";
    connection.query(query, [email], (error, results) => {
      if (error) {
        console.error("Error executing query:", error);
        reject(
          "An error occurred while processing your request. Please try again."
        );
      } else {
        console.log("SQL Query:", query, "email:", email);
        const exists = results[0].count > 0;
        resolve({ exists });
      }
    });

    connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
      connection
    );
  });
};

// Helper function to send OTP to the user's email
async function sendOTPByEmail(email, otp) {
  const subject = "Reset Password OTP"; // Specify the subject of the email
  const content = `Your OTP to reset the password is: ${otp}`; // Specify the content of the email

  // Call the `sendEmail` function from `emailSender.js` to send the email
  await sendEmail(email, subject, content);
}

// Helper function to store OTP in the database
async function storeOTPInDatabase(email, otp, expiryTime) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  return new Promise(async (resolve, reject) => {
    // Fetch Contact_Number from the login database
    const contactNumberQuery =
      "SELECT contact_number FROM login WHERE email = ?";
    const contactNumberResults = await queryDatabase(contactNumberQuery, [
      email,
    ]);

    if (contactNumberResults.length === 1) {
      const contactNumber = contactNumberResults[0].Contact_Number;

      // Store the OTP, email, expiry time, and contact number in the otps database
      const query =
        "INSERT INTO otps (email, otp, expiry_time, contact_number) VALUES (?, ?, ?, ?)";
      const queryPayload = [email, otp, expiryTime, contactNumber];

      connection.query(query, queryPayload, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    } else {
      reject(new Error("Contact_Number not found for the given email"));
    }

    connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
      connection
    );
  });
}

// Helper function to execute a query on the database
async function queryDatabase(query, params) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  return new Promise((resolve, reject) => {
    connection.query(query, params, (error, results) => {
      if (error) {
        reject(error);
      } else {
        resolve(results);
      }
    });

    connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
      connection
    );
  });
}

// Function to store OTP in the database and send it to the user's email
exports.sendOTP = async function (email) {
  try {
    // Generate a 5-digit plain/text OTP
    const plainOTP = Math.floor(10000 + Math.random() * 90000);

    // Store the hashed OTP in the database with an expiry time (e.g., 5 minutes)
    // const hashedOTP = await bcrypt.hash(plainOTP.toString(), 10);
    const expiryTime = Date.now() + 5 * 60 * 1000; // 5 minutes in milliseconds

    // Store the hashed OTP, expiry time, and contact number in the database
    await storeOTPInDatabase(email, plainOTP, expiryTime);

    // Send the plain OTP to the user's email
    await sendOTPByEmail(email, plainOTP);

    // Delete expired OTPs from the database
    // await deleteExpiredOTPs();

    console.log("OTP successfully sent and stored.");
  } catch (error) {
    console.error("Error sending OTP:", error);
    // Handle error, e.g., log the error or throw it for further handling
    throw new Error(
      "An error occurred while processing your request. Please try again."
    );
  }
};

// Function to verify OTP
exports.verifyOTP = async function (email, enteredOTP) {
  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  return new Promise((resolve, reject) => {
    const current_Time = new Date().getTime();
    const query = `SELECT * FROM otps WHERE email = ? AND expiry_time > ${current_Time}`;

    connection.query(query, [email], async (error, results) => {
      if (error) {
        console.error("Error executing query:", error);
        reject(error);
      } else {
        console.log("SQL Query:", query, "email:", email);

        // Check if there are any valid OTPs
        if (results.length > 0) {
          const storedOTP = results[0].otp;

          // Compare the entered OTP with the stored OTP
          const isValidOTP = enteredOTP === storedOTP;
          console.log("ISVALIDOTP ===", isValidOTP);

          resolve({ isValidOTP, email });
        } else {
          // No valid OTP found
          resolve({ isValidOTP: false, email });
        }
      }
    });

    connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
      connection
    );
  });
};

// Function to update the password in the login database
exports.resetPassword = async function (email, newPassword) {
  // hash the new password
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  const connection =
    connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

  return new Promise((resolve, reject) => {
    const query = "UPDATE login SET password = ? WHERE email = ?";
    connection.query(query, [hashedPassword, email], (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });

    connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
      connection
    );
  });
};

exports.fetchUserData = function (request, response) {
  try {
    // Get the token from the request body
    const token = request.body.user_id;

    // Verify the token
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        // Token verification failed
        console.error("Token verification failed:", err);
        return response.status(401).json({ message: "Unauthorized" });
      }

      // Token verified successfully, extract user_id
      const userId = decoded.user_id;

      // Use userId to fetch user-specific data from the database
      const connection =
        connectionProvider.mysqlConnectionStringProvider.getMysqlConnection();

      // SQL query to fetch user data, course information, and total chapters
      const selectQuery = `
      SELECT
      login.user_id,
      courses_info.course_name,
      courses_info.status,
      subjects_info.subject_name,
      COUNT(chapters_info.chapter_id) AS total_chapters
      FROM login
      LEFT JOIN courses_info ON login.user_id = courses_info.user_id
      LEFT JOIN chapters_info ON courses_info.course_id = chapters_info.course_id
      LEFT JOIN subjects_info ON courses_info.subject_id = subjects_info.subject_id
      WHERE login.user_id = ?
      GROUP BY courses_info.course_id;
  
      `;
      const selectQueryPayload = [userId];

      connection.query(selectQuery, selectQueryPayload, (err, rows, fields) => {
        connectionProvider.mysqlConnectionStringProvider.closeMysqlConnection(
          connection
        );

        if (err) {
          console.error("Error executing database query:", err);
          return response.status(500).json({ error: err.message });
        }

        console.log("User Data:", rows);
        response.json({ userData: rows });
      });
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    response.status(500).json({ error: "Internal Server Error" });
  }
};

// ------------------------Working Code ---------------------------------------

// ------------------------Testing Code ---------------------------------------
