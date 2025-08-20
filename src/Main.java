import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

import org.bouncycastle.crypto.generators.SCrypt;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.security.SecureRandom;



public class Main {
    static byte[] masterPassword = null; // This will hold the hashed master password

    public static void main(String[] args) {

        int iterations = 50;
        int salt = 190213; // Salt value for master password

        JFrame frame = createFrameBoilerPlate();
        JPasswordField passwordField = new JPasswordField(20);



        passwordField.setEchoChar('*');
        passwordField.setToolTipText("Enter your password here");
        JPanel encryptPanel = new JPanel();
        encryptPanel.add(passwordField);

        //Submit button to handle password input
        JButton submitButton = new JButton("Submit");
        submitButton.addActionListener(e -> {
            char[] password = passwordField.getPassword();
            password.toString();
            // Handle the password input, e.g., validate it or process it
            System.out.println("Password entered: " + new String(password));

            for(int i=0; i<iterations; i++) {
                masterPassword = SCrypt.generate(String.valueOf(password).getBytes(StandardCharsets.UTF_8), String.valueOf(salt).getBytes(StandardCharsets.UTF_8), 16384, 8, 1, 32);
            }
            String passwordText = Base64.getEncoder().encodeToString(masterPassword);

            JOptionPane.showMessageDialog(frame, "Password submitted successfully!, Your encrypted password is: " + passwordText, "Success", JOptionPane.INFORMATION_MESSAGE);

            // Check if the file exists, if not create it
            fileCreate();

            frame.setVisible(false);
            try {
                displayMainMenu();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }

        });

        encryptPanel.add(submitButton);


        frame.add(encryptPanel);
        frame.setLocationRelativeTo(null); // Center the frame on the screen
        frame.setVisible(true);
    }



    public static void fileCreate(){
        //This method will be called if the user has not created a file yet.

        // Check if the file already exists
        File file = new File("passwords.json");
        if(!file.exists()) {
            //If the file does not exist then we create it
            try {
                FileWriter fileWriter = new FileWriter("passwords.json", true);
                JSONObject initialObject = new JSONObject();
                fileWriter.write(initialObject.toJSONString());
                fileWriter.close();
            } catch (java.io.IOException e) {
                System.out.println("An error occurred while creating the file.");
                e.printStackTrace();
            }
        }
    }



    public static void displayMainMenu() throws IOException, ParseException {
        // This method can be used to display the main menu of the application
        System.out.println("Displaying main menu...");
        // Add your menu logic here

        JFrame frame = createFrameBoilerPlate();

        JPanel passwordPanel = new JPanel();
        passwordPanel.setLayout(new GridLayout(0,1));
        JLabel passwordLabel = new JLabel("Your Passwords");
        passwordPanel.add(passwordLabel);

        // Read the file and display the passwords
        try {
            File file = new File("passwords.json");

            // If the file is empty, we will not be able to decrypt it.
            if (file.exists() && file.length() > 0) {

                Object o = new JSONParser().parse(new FileReader("passwords.json"));
                JSONObject passwordList = (JSONObject) o;
                for(Object passObj : passwordList.values()) {
                    JSONObject details = (JSONObject) passObj;
                    try {
                        decryptObject(details);
                    } catch (Exception e) {
                        System.out.println("Error decrypting object: " + e.getMessage());
                    }

                    String name = (String) details.get("name");
                    String password = (String) details.get("password");


                    JLabel passwordEntry = new JLabel("Name: " + name + ", Password: " + password);

                    passwordPanel.add(passwordEntry);
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("File not found. Please create a password first.");
        }


        JPanel optionsPanel = new JPanel();
        JButton addPasswordButton = new JButton("Add Password");
        addPasswordButton.addActionListener(e -> {
            // Call the method to display the password add menu
            frame.setVisible(false); // Hide the current frame
            displayPasswordAddMenu();
        });

        JButton removePasswordButton = new JButton("Remove Password");

        optionsPanel.add(addPasswordButton);
        optionsPanel.add(removePasswordButton);


        frame.add(passwordPanel);
        frame.add(optionsPanel);
        frame.setLocationRelativeTo(null); // Center the frame on the screen
        frame.setVisible(true);
    }



    public static void displayPasswordAddMenu() {
        JFrame frame = createFrameBoilerPlate();

        JPanel addPasswordPanel = new JPanel();
        JTextField nameField = new JTextField(20);
        nameField.setToolTipText("Enter the name of the password");
        JTextField passwordField = new JTextField(20);
        passwordField.setToolTipText("Enter your password here");


        JLabel addPasswordLabel = new JLabel("Add Name and Password");


        addPasswordPanel.add(addPasswordLabel);
        addPasswordPanel.add(nameField);
        addPasswordPanel.add(passwordField);


        JButton submitButton = new JButton("Submit");
        submitButton.addActionListener(e -> {
            String name = nameField.getText();
            String password = passwordField.getText();


            //Before we store it, we need to encrypt the password AND name.

            //Generate a random salt value
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16]; // 16 bytes for AES
            secureRandom.nextBytes(salt);
            //Convert Salt to Base64 for storage
            String base64Salt = Base64.getEncoder().encodeToString(salt);


            JSONObject details = new JSONObject();
            details.put("name", name);
            details.put("password", password);
            details.put("iv", "");
            details.put("salt", base64Salt);

            try {
                encryptObject(details);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                     InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                throw new RuntimeException(ex);
            }

            //Retrieve the top level JSONObject from the file
            File file = new File("passwords.json");
            Object o = null;
            try {
                o = new JSONParser().parse(new FileReader("passwords.json"));
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            JSONObject passwordList = (JSONObject) o;

            // Add the new password details to the JSON object
            passwordList.put(passwordList.size() + 1, details);


            FileWriter fileWriter = null;
            try{
                fileWriter = new FileWriter("passwords.json", false); // Overwrite the file
                fileWriter.write(passwordList.toJSONString());
                fileWriter.close();
            } catch (IOException ex) {
                System.out.println("An error occurred while writing to the file.");
                ex.printStackTrace();
            }

            frame.setVisible(false);
            try {
                displayMainMenu();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        });


        frame.add(addPasswordPanel);
        frame.add(submitButton);

        frame.setLocationRelativeTo(null); // Center the frame on the screen
        frame.setVisible(true);
    }



    public static JFrame createFrameBoilerPlate(){
        JFrame frame = new JFrame();

        frame.setLayout(new GridLayout(2,1));
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(300, 200);

        return frame;
    }


    public static void encryptObject(JSONObject details) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        //Extract Values
        String name = (String) details.get("name");
        String password = (String) details.get("password");
        String salt = (String) details.get("salt");

        String seasonedName = name + salt; // Combine name with salt for encryption
        String seasonedPassword = password + salt; // Combine password with salt for encryption

        //Create secret key
        SecretKey secretKey = new SecretKeySpec(masterPassword, "AES");

        //Generate IV value
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        //Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        //Encrypt the name and password
        byte[] encryptedName = cipher.doFinal(seasonedName.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedPassword = cipher.doFinal(seasonedPassword.getBytes(StandardCharsets.UTF_8));

        //Convert to base64 for storage
        String base64EncryptedName = Base64.getEncoder().encodeToString(encryptedName);
        String base64EncryptedPassword = Base64.getEncoder().encodeToString(encryptedPassword);

        //Create JSON object to store encrypted data
        details.put("name", base64EncryptedName);
        details.put("password", base64EncryptedPassword);
        details.put("iv", Base64.getEncoder().encodeToString(iv));
    }


    public static void decryptObject(JSONObject details) throws IOException, ParseException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Extract the encrypted name, password, and IV
        String encryptedName = (String) details.get("name");
        String encryptedPassword = (String) details.get("password");
        String iv = (String) details.get("iv");
        String salt = (String) details.get("salt");

        // Decode Base64 values
        byte[] decodedName = Base64.getDecoder().decode(encryptedName);
        byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);
        byte[] decodedIv = Base64.getDecoder().decode(iv);
        byte[] decodedSalt = Base64.getDecoder().decode(salt);

        System.out.println("IV: " + iv);
        System.out.println("Salt: " + salt);

        // Create secret key
        SecretKey secretKey = new SecretKeySpec(masterPassword, "AES");

        // Create IV parameter spec
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decodedIv);

        // Create cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        // Decrypt the name and password
        String decryptedName = new String(cipher.doFinal(decodedName), StandardCharsets.UTF_8);
        String decryptedPassword = new String(cipher.doFinal(decodedPassword), StandardCharsets.UTF_8);

        // Remove the salt from the decrypted values
        decryptedName = decryptedName.replace(salt, "");
        decryptedPassword = decryptedPassword.replace(salt, "");

        System.out.println("Decrypted Name: " + decryptedName);
        System.out.println("Decrypted Password: " + decryptedPassword);

        details.put("name", decryptedName);
        details.put("password", decryptedPassword);
    }
}