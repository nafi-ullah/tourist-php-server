<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Allow-Methods: *");

include 'DbConnect.php';
include 'vendor/autoload.php'; // Composer autoload

use Firebase\JWT\JWT;

$objDb = new DbConnect;
$conn = $objDb->connect();

// $secret_key = "YOUR_SECRET_KEY";
// $issuer_claim = "THE_ISSUER"; // this can be the servername

$method = $_SERVER['REQUEST_METHOD'];
switch($method) {
    case "GET":
        //http://localhost/api/users/posts
        //http://localhost/api/users/users
        $path = explode('/', $_SERVER['REQUEST_URI']);
        $table = isset($path[3]) ? $path[3] : null;
        
        switch ($table) {
            case "users":
                $sql = "SELECT userid, username, fullname, profilepic, email, bio, countrylist FROM users";
                if (isset($path[4]) && is_numeric($path[4])) {
                    $sql .= " WHERE userid = :userid";
                    $stmt = $conn->prepare($sql);
                    $stmt->bindParam(':userid', $path[4]);
                    $stmt->execute();
                    $users = $stmt->fetch(PDO::FETCH_ASSOC);
                } else {
                    $stmt = $conn->prepare($sql);
                    $stmt->execute();
                    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                }

                echo json_encode($users);
                break;

            case "posts":
                $sql = "SELECT postid, userid, headline, country, caption, picture FROM posts";
                if (isset($path[4]) && is_numeric($path[4])) {
                    $sql .= " WHERE userid = :userid";
                    $stmt = $conn->prepare($sql);
                    $stmt->bindParam(':userid', $path[4]);
                    $stmt->execute();
                    $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } else {
                    $stmt = $conn->prepare($sql);
                    $stmt->execute();
                    $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
                }

                echo json_encode($posts);
                break;

            default:
                echo json_encode(['error' => 'Invalid table name']);
                break;
        }
        break;

    case "POST":
        $data = json_decode( file_get_contents('php://input') );

        if($data->table == "users"){


        if ($data->action == "login") {
            $email = $data->email;
            $password = $data->password;

            $sql = "SELECT * FROM users WHERE email = :email";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                if (password_verify($password, $user['password'])) {
                    $secret_key = 'tourist_secret_key';

            $jwt_payload = [
                'iss' => 'naficoder',
                'iat' => time(),
                'exp' => strtotime("+1 hour"),
                'userid' => $user['userid'],
                'username' => $user['username']
                // You can add more data to the payload if needed
            ];
           

            $jwt_token = JWT::encode($jwt_payload, $secret_key, 'HS256');
                    echo json_encode(
                        array(
                            "message" => "Successful login.",
                            'user' => $user,
                            "jwt" => $jwt_token,
                          
                        ));
                } else {
                    http_response_code(401);
                    echo json_encode(array("message" => "Login failed. Incorrect credentials."));
                }
            } else {
                http_response_code(401);
                echo json_encode(array("message" => "Login failed. User not found."));
            }
        } elseif ($data->action == "register") {
            $username = $data->username;
            $fullname = $data->fullname;
            $email = $data->email;
            $password = password_hash($data->password, PASSWORD_BCRYPT); // encrypt password
            // Other fields

            $sql = "INSERT INTO users(username, fullname, email, password) VALUES(:username, :fullname, :email, :password)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':fullname', $fullname);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $password);

            if($stmt->execute()) {
                $response = ['status' => 1, 'message' => 'User registered successfully.'];
            } else {
                $response = ['status' => 0, 'message' => 'Failed to register user.'];
            }
            echo json_encode($response);
        } else {
            http_response_code(400);
            echo json_encode(array("message" => "Invalid action."));
        }
        //------------------------------posts tables post------------------------------------------------------------

    }else if($data->table == "posts"){
       
        $sql = "INSERT INTO posts(userid, headline, country, caption, picture) VALUES(:userid, :headline, :country, :caption, :picture)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $data->userid);
        $stmt->bindParam(':headline', $data->headline);
        $stmt->bindParam(':country', $data->country);
        $stmt->bindParam(':caption', $data->caption);
        $stmt->bindParam(':picture', $data->picture);

        if($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Record created successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to create record.'];
        }
        echo json_encode($response);
    }



        break;

    case "PUT":
        // Update operation
        $user = json_decode( file_get_contents('php://input') );
        if($user->table == "users"){

        $sql = "UPDATE users SET username = :username, fullname = :fullname, profilepic = :profilepic, email = :email, password = :password, bio = :bio, countrylist = :countrylist WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $user->userid);
        $stmt->bindParam(':username', $user->username);
        $stmt->bindParam(':fullname', $user->fullname);
        $stmt->bindParam(':profilepic', $user->profilepic);
        $stmt->bindParam(':email', $user->email);
        $stmt->bindParam(':password', $user->password);
        $stmt->bindParam(':bio', $user->bio);
        $stmt->bindParam(':countrylist', $user->countrylist);
       

        if($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Record updated successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to update record.'];
        }
        echo json_encode($response);

//-------------------------------------posts tables put--------------------------------------------

    }else if($user->table == "posts"){
        $sql = "UPDATE posts SET userid = :userid, headline = :headline, country = :country, caption = :caption, picture = :picture WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $user->id);
        $stmt->bindParam(':userid', $user->userid);
        $stmt->bindParam(':headline', $user->headline);
        $stmt->bindParam(':country', $user->country);
        $stmt->bindParam(':caption', $user->caption);
        $stmt->bindParam(':picture', $user->picture);

        if($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Record updated successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to update record.'];
        }
        echo json_encode($response);

    }




        break;

    case "DELETE":
        // Delete operation
        $sql = "DELETE FROM users WHERE userid = :userid";
        $path = explode('/', $_SERVER['REQUEST_URI']);

        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':userid', $path[3]);

        if($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Record deleted successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to delete record.'];
        }
        echo json_encode($response);
        break;
}
