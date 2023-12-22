const express = require('express');
const router = express.Router();
const userDao = require('./server/Dao/usersDao.js')


router.post('/check-email-exists', async (req, res) => {
  try {
    // const { email } = req.body;
    // const exists = await userDao.checkEmailExists(email);

    console.log("CHECK EMAIL ROUTER")
    const email = req.body.email;
    console.log('EMAIL:', email)
    const exists = await userDao.checkEmailExists(email);
    res.json({ exists });
  } catch (error) {
    console.error('Error checking email exists:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



router.post('/send-otp', async (req, res) => {
  try {
    const { email, contactNumber } = req.body;
    await userDao.sendOTP(email, contactNumber);
    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




router.post('/verify-otp', async (req, res) => {
  try {
    console.log('Received OTP verification request:', req.body);
    const { email, enteredOTP } = req.body;

    // Call the function to verify OTP
    const result = await userDao.verifyOTP(email, enteredOTP);

    // Check if OTP is valid
    if (result.isValidOTP) {
      // Access the email from the result and use it if needed
      const { email: userEmail } = result;
      res.json({ isValidOTP: true, message: 'OTP verification successful', userEmail });
    } else {
      res.status(401).json({ isValidOTP: false, message: 'Invalid OTP or OTP expired' });
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


router.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // Call the function to update the password
    await userDao.resetPassword(email, newPassword);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



// New route for fetching user data
router.post('/fetch-user-data', async (req, res) => {
  console.log('Received request to /fetch-user-data');
  try {
    await userDao.fetchUserData(req, res);
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Export the router
module.exports = router;