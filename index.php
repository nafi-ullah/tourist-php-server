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
                $sql = "
                SELECT 
                    posts.postid, 
                    posts.userid, 
                    posts.headline, 
                    posts.country, 
                    posts.caption, 
                    posts.picture, 
                    posts.timestamp, 
                    users.profilepic, 
                    users.fullname, 
                    users.username, 
                    (SELECT COUNT(*) FROM comments WHERE comments.postid = posts.postid) AS comment_count
                FROM 
                    posts 
                INNER JOIN 
                    users ON posts.userid = users.userid
                ORDER BY posts.postid DESC
            ";
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

           case "comments":
                $sql = "SELECT users.username, comments.commentid, comments.postid, comments.comment, comments.timestamp FROM comments INNER JOIN users ON comments.userid = users.userid";
                if (isset($path[4]) && is_numeric($path[4])) {
                    $sql .= " WHERE comments.postid = :postid";
                    $stmt = $conn->prepare($sql);
                    $stmt->bindParam(':postid', $path[4]);
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


    }else if($data->table == "comments"){
       
        $sql = "INSERT INTO comments( postid, userid, comment) VALUES(:postid, :userid, :comment)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':postid', $data->postid);
        $stmt->bindParam(':userid', $data->userid);
        $stmt->bindParam(':comment', $data->comment);
       

        if($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Comment created successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to create record.'];
        }
        echo json_encode($response);
    }

        break;

    case "PUT":
        // Update operation
       

        $path = explode('/', $_SERVER['REQUEST_URI']);
        $table = isset($path[3]) ? $path[3] : null;

        switch ($table) {
            case "users":
             
                $user = json_decode( file_get_contents('php://input') );
                $mypassword = password_hash($user->password, PASSWORD_BCRYPT);

                $sql = "UPDATE users SET username = :username, fullname = :fullname, profilepic = :profilepic,coverpic = :coverpic, email = :email, password = :password, bio = :bio WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->bindParam(':userid', $user->userid);
                $stmt->bindParam(':username', $user->username);
                $stmt->bindParam(':fullname', $user->fullname);
                $stmt->bindParam(':profilepic', $user->profilepic);
                $stmt->bindParam(':email', $user->email);
               
                $stmt->bindParam(':password', $mypassword);
                $stmt->bindParam(':bio', $user->bio);
                $stmt->bindParam(':coverpic', $user->coverpic);
               
        
                if($stmt->execute()) {
                    $response = ['status' => 1, 'message' => 'Record updated successfully.'];
                } else {
                    $response = ['status' => 0, 'message' => 'Failed to update record.'];
                }
                echo json_encode($response);


                break;
    //-------------------------------------posts tables put--------------------------------------------

            case "posts":
                $post = json_decode(file_get_contents('php://input'));
                $sql = "UPDATE posts SET headline = :headline, country = :country, caption = :caption, picture = :picture WHERE postid = :postid";
                $stmt = $conn->prepare($sql);
                $stmt->bindParam(':postid', $path[4]);
                $stmt->bindParam(':headline', $post->headline);
                $stmt->bindParam(':country', $post->country);
                $stmt->bindParam(':caption', $post->caption);
                $stmt->bindParam(':picture', $post->picture);

                if ($stmt->execute()) {
                    $response = ['status' => 1, 'message' => 'Post updated successfully.'];
                } else {
                    $response = ['status' => 0, 'message' => 'Failed to update post.'];
                }
                echo json_encode($response);
                break;
//------------------------------------------comments------------------------------------------------------
            case "comments":
                $post = json_decode(file_get_contents('php://input'));
                $sql = "UPDATE comments SET comment = :comment  WHERE commentid = :commentid";
                $stmt = $conn->prepare($sql);
                $stmt->bindParam(':commentid', $path[4]);
                $stmt->bindParam(':comment', $post->comment);
           

                if ($stmt->execute()) {
                    $response = ['status' => 1, 'message' => 'Comment updated successfully.'];
                } else {
                    $response = ['status' => 0, 'message' => 'Failed to update post.'];
                }
                echo json_encode($response);
                break;

            default:
                echo json_encode(['error' => 'Invalid table name']);
                break;
        }


        break;

    case "DELETE":
        
        $path = explode('/', $_SERVER['REQUEST_URI']);
        $table = isset($path[3]) ? $path[3] : null;        

        switch ($table) {
            case "users":
        // Handle deleting user information
               $sql = "DELETE FROM users WHERE userid = :userid";

            $stmt = $conn->prepare($sql);
             $stmt->bindParam(':userid', $path[4]);

           if($stmt->execute()) {
                $response = ['status' => 1, 'message' => 'Record deleted successfully.'];
           } else {
                 $response = ['status' => 0, 'message' => 'Failed to delete record.'];
          }
        echo json_encode($response);
        break;

    case "posts":
        $sql = "DELETE FROM posts WHERE postid = :postid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':postid', $path[4]);

        if ($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Post deleted successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to delete post.'];
        }
        echo json_encode($response);
        break;
    
    
    case "comments":
        $sql = "DELETE FROM comments WHERE commentid = :commentid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':commentid', $path[4]);

        if ($stmt->execute()) {
            $response = ['status' => 1, 'message' => 'Post deleted successfully.'];
        } else {
            $response = ['status' => 0, 'message' => 'Failed to delete post.'];
        }
        echo json_encode($response);
        break;

    default:
        echo json_encode(['error' => 'Invalid table name']);
        break;
}




        break;


        default:
        echo json_encode(['error' => 'Invalid request method']);
        break;
}
