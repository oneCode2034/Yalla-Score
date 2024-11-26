<?php

class Model
{

    private $wp_error;
    private $wp_info;
    private $post_array = array();
    private $get_array = array();
    private $firstname = "";
    private $lastname = "";
    private $username = "";
    private $email = "";
    private $pass = "";
    private $comPass = "";
    private $gender = "";
    private $reCaptcha;
    private $image_id = "";

    public function __construct()
    {
        $this->wp_error = new WP_Error(null, null, null);
        $this->wp_info = new WP_Error(null, null, null);
        $this->reCaptcha = new \reCAPTCHA();
    }

    /** allow the request data to be set * */
    public function set_request_params($post_array, $get_array)
    {
        $this->post_array = $post_array;
        $this->get_array = $get_array;
        if (isset($this->post_array['ferl_username']))
            $this->username = $this->post_array['ferl_username'];
        if (isset($this->get_array['username']))
            $this->username = $this->get_array['username'];
    }

    /** methods required by the View class * */
    public function get_error_codes()
    {
        return $this->wp_error->get_error_codes();
    }

    public function get_info_codes()
    {
        return $this->wp_info->get_error_codes();
    }

    public function get_error_message($code)
    {
        return $this->wp_error->get_error_message($code);
    }

    public function get_info_message($code)
    {
        return $this->wp_info->get_error_message($code);
    }

    public function get_firstname()
    {
        return $this->firstname;
    }

    public function get_lastname()
    {
        return $this->lastname;
    }

    public function get_username()
    {
        return $this->username;
    }

    public function get_email()
    {
        return $this->email;
    }

    /** methods to handle form submissions * */
public function login_user()
{
    // make sure we have a username and the nonce is correct
    if (isset($this->post_array['ferl_username']) && wp_verify_nonce($this->post_array['ferl_login_nonce'], 'ferl-login-nonce'))
    {
        $user_login = $this->post_array['ferl_username'];
        global $myRedux;
        $user = (is_email($user_login)) ? get_user_by('email', $user_login) : get_user_by('login', $user_login);
        
        if ($myRedux['reCaptcha'] == "yes") 
        {
            $recaptcha = $_POST['g-recaptcha-response'];
            $valid = $this->reCaptcha::validate($recaptcha);
            if(!$valid)
            {
                $this->wp_error->add('firstname_empty', __('Please check the captcha'));
            }
        }
        
        if (!$user_login || $user_login == '')
        {
            // if no username was entered
            $this->wp_error->add('empty_username', __('Please enter the username'));
        }
        else
        {
            if (!$user)
            {
                // if the user name doesn't exist
                $this->wp_error->add('invalid_username', __('Incorrect information'));
            }
        }

        if (!isset($this->post_array['ferl_user_pass']) || $this->post_array['ferl_user_pass'] == '')
        {
            // if no password was entered
            $this->wp_error->add('empty_password', __('Incorrect information'));
        }
        else
        {
            if ($user)
            {
                // check the user's login with their password
                if (!wp_check_password($this->post_array['ferl_user_pass'], $user->user_pass, $user->ID))
                {
                    // if the password is incorrect for the specified user
                    $this->wp_error->add('invalid_password', __('Incorrect password'));
                }
            }
        }

        // retrieve all error messages
        $errors = $this->wp_error->get_error_messages();
        // only log the user in if there are no errors
        if (empty($errors))
        {
            $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $redirect_page = $current_url;
            wp_set_auth_cookie($user->ID, true);
            wp_set_current_user($user->ID, $user_login);
            do_action('wp_login', $user_login);
            wp_redirect($redirect_page);
            exit;
        }
    }
}


    public function logout_user()
    {
        wp_logout();
    }
   public function profile_user()
{
    $userID = getUser("ID");

    if (!function_exists('wp_handle_upload'))
    {
        require_once(ABSPATH . 'wp-admin/includes/file.php');
    }
    if (!function_exists('media_handle_upload'))
    {
        require_once(ABSPATH . 'wp-admin/includes/media.php');
    }
    if (!function_exists('wp_generate_attachment_metadata'))
    {
        require_once(ABSPATH . 'wp-admin/includes/image.php');
    }

    if (wp_verify_nonce($this->post_array['ferl_profile_nonce'], 'ferl-profile-nonce'))
    {
        $firstname = $this->post_array["ferl_firstname"];
        $lastname = $this->post_array["ferl_lastname"];
        $email = $this->post_array["ferl_email"];
        $gender = $this->post_array["ferl_gender"];
        $pass1 = $this->post_array['ferl_user_pass1'];
        $pass2 = $this->post_array['ferl_user_pass2'];
        $this->firstname = $firstname;
        $this->lastname = $lastname;
        $this->email = $email;
        $this->gender = $gender;
        $image = $_FILES['ferl_image'];

        if (!current_user_can('edit_user', $userID))
        {
            $this->wp_error->add('permission_denied', __('You do not have permission to edit this file.'));
        }

        if (trim($firstname) == '')
        {
            $this->wp_error->add('firstname_empty', __('Please enter the first name'));
        }
        if (trim($lastname) == '')
        {
            $this->wp_error->add('lastname_empty', __('Please enter the last name'));
        }
        if (trim($email) == '')
        {
            $this->wp_error->add('email_empty', __('Please enter the email address'));
        }
        else
        {
            if (!is_email($email))
            {
                $this->wp_error->add('email_invalid', __('Please enter a valid email address'));
            }
            if (get_userdata($userID)->user_email != $email && email_exists($email))
            {
                $this->wp_error->add('email_exists', __('The email address is already registered.'));
            }
        }

        if (trim($gender) == '')
        {
            $this->wp_error->add('gender_empty', __('Please enter the gender'));
        }
        else
        {
            if (!in_array($gender, array("male", "female")))
            {
                $this->wp_error->add('gender_invalid', __('Invalid gender input'));
            }
        }

        if ($pass1 && $pass2)
        {
            if (strlen($pass1) >= 5 && strlen($pass2) >= 5)
            {
                if ($pass1 == $pass2)
                {
                    if (empty($this->wp_error->get_error_messages()))
                    {
                        wp_update_user(array('ID' => $userID, 'user_pass' => $pass1));
                    }
                }
                else
                {
                    $this->wp_error->add('password_mismatch', __('Passwords do not match.'));
                }
            }
            else
            {
                $this->wp_error->add('password_too_short', __('Password must be at least 5 characters long.'));
            }
        }

        if (!empty($image['name']))
        {
            $allowed_file_types = array('image/jpeg', 'image/png', 'image/gif');
            if (!in_array($image['type'], $allowed_file_types))
            {
                $this->wp_error->add('invalid_file_type', __('File type not allowed.'));
            }

            $max_file_size = 5 * 1024 * 1024; // 5MB
            if ($image['size'] > $max_file_size)
            {
                $this->wp_error->add('file_too_large', __('File size exceeds the allowed limit.'));
            }

            if (empty($this->wp_error->get_error_messages()))
            {
                $upload_overrides = array('test_form' => false);
                $this->image_id = media_handle_upload('ferl_image', 0, array(), $upload_overrides);

                if (is_wp_error($this->image_id))
                {
                    $this->wp_error->add('image_upload_failed', __('Image upload failed: ' . $this->image_id->get_error_message()));
                }
                else
                {
                    update_user_meta($userID, 'image', $this->image_id);
                }
            }
        }

        $errors = $this->wp_error->get_error_messages();
        if (empty($errors))
        {
            $args = array(
                'ID' => $userID,
                'user_email' => $email,
            );
            wp_update_user($args);
            update_user_meta($userID, "first_name", $firstname);
            update_user_meta($userID, "last_name", $lastname);
            update_user_meta($userID, "gender", $gender);
            $this->wp_info->add('updated_profile', __('Profile data updated successfully.'));
        }
    }
}


public function change_password()
      {
          $pw_chars = array('!', '@', '#', '?', '$', '%', '^', '&', '*', '_', '-');
          if (!empty($this->post_array['username']) && array_key_exists('ferl_password_nonce', $this->post_array) && wp_verify_nonce($this->post_array['ferl_password_nonce'], 'ferl-password-nonce'))
          {
              $current_user = get_user_by('login', $this->post_array['username']);
              $old_password = $this->post_array['ferl_user_old_pass'];
              $pass1 = $this->post_array['ferl_user_pass1'];
              $pass2 = $this->post_array['ferl_user_pass2'];

              if (!wp_check_password($old_password, $current_user->user_pass, $current_user->ID))
              {
                  $this->wp_error->add('invalid_old_password', __('The old password is incorrect. Password not updated.'));
              }
              else
              {
                  if (strlen($pass1) > 0 && strlen($pass2) > 0)
                  {
                      if ($pass1 == $pass2)
                      {
                          if (strlen($pass1) < 5)
                          {
                              $this->wp_error->add('invalid_password', __('Password must be at least 5 characters long. Password not updated.'));
                          }
                          else
                          {
                              if (!ctype_alnum(str_replace($pw_chars, '', $pass1)))
                              {
                                  $this->wp_error->add('invalid_password', __("Password can only contain alphanumeric characters and the following special characters: <br />" . implode(' ', $pw_chars) . "  <br/>Password not updated."));
                              }
                          }
                      }
                      else
                      {
                          $this->wp_error->add('invalid_password', __('The passwords you entered do not match. Password not updated.'));
                      }
                  }
                  else
                  {
                      $this->wp_error->add('invalid_password', __('Password must be at least 5 characters long. Password not updated.'));
                  }
              }

              // إذا كانت هناك رسائل أخطاء
              $errors = $this->wp_error->get_error_messages();
              if (empty($errors))
              {
                  // إذا لم يكن هناك أخطاء، نقوم بتحديث كلمة المرور
                  wp_update_user(array('ID' => $current_user->ID, 'user_pass' => esc_attr($pass1)));
                  $this->wp_info->add('updated_password', __('Your password has been updated.'));
              }
          }
      }

function lost_password()
{
    global $wpdb;

    if (isset($this->post_array["submit"]) && wp_verify_nonce($this->post_array['ferl_request_password_reset_nonce'], 'ferl-request-password-reset-nonce'))
    {
        $email = $this->post_array["ferl_email"];
        global $myRedux;
        
        if ($myRedux['reCaptcha'] == "yes") 
        {
            $recaptcha =  $_POST['g-recaptcha-response'];
            $valid = $this->reCaptcha::validate($recaptcha);
            if(!$valid)
            {
                $this->wp_error->add('firstname_empty', __('Please verify the reCAPTCHA.'));
            }
        }
        if (trim($email) == '')
        {
            $this->wp_error->add('email_empty', __('Please enter an email address.'));
        }
        else
        {
            $email = strtolower($email); 
        }
        if (!email_exists($email))
        {
            $this->wp_error->add('email_not_registered', __('No such email is registered.'));
        }
        else
        {
            $the_user = get_user_by('email', $email); 
        }

        $errors = $this->wp_error->get_error_messages();
        if (empty($errors))
        {
            $key = wp_generate_password(20, false);
            $wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_email' => $email)); 
            $username = $the_user->user_login;  
            $to = $the_user->user_email;
            $body = "..";
            $body .= "\nHello " . $the_user->display_name . "!";
            $body .= "\nSomeone has requested to reset your password at \"" . get_bloginfo('name') . "\".";
            $body .= "\nIf this was a mistake, simply ignore this message and nothing will happen.";
            $body .= "\nTo reset your password, please visit the following address:";
            $body .= "\n " . site_url() . "/confirm-reset-password?action=reset-password&username=" . $username . "&key=" . $key . "";
            $body .= "\n";
            wp_mail($to, "[" . get_bloginfo('name') . "] Password reset request for " . $username, $body);
            $this->wp_info->add('updated_password', __('A password recovery email has been sent to your email address.'));
        }
    }
}
  public function register_user()
{
    if (isset($this->post_array['ferl_username']) && wp_verify_nonce($this->post_array['ferl_register_nonce'], 'ferl-register-nonce'))
    {
        $username = $this->post_array["ferl_username"];
        $email = $this->post_array["ferl_email"];
        $pass = $this->post_array["ferl_pass"];
        $conPass = $this->post_array["ferl_conpass"];
        $this->email = $email;
        $this->pass = $pass;
        $this->comPass = $conPass;
        global $myRedux;
          $user = get_user_by('login', $username);
        if ($myRedux['reCaptcha'] == "yes") 
        {
            $recaptcha = $_POST['g-recaptcha-response'];
            $valid = $this->reCaptcha::validate($recaptcha);
            if (!$valid)
            {
                $this->wp_error->add('firstname_empty', __('Please verify the captcha.'));
            }
        }
        if (trim($username) == '')
        {
            $this->wp_error->add('username_empty', __('Please enter a username.'));
        }
        else
        {
            if (!$this->is_valid_username($username))
            {
                $this->wp_error->add('username_invalid', __('Invalid username.'));
            }
            else
            {
                if (username_exists($username))
                {
                    $this->wp_error->add('username_unavailable', __('Username already exists.'));
                }
            }
        }
        if (trim($email) == '')
        {
            $this->wp_error->add('email_empty', __('Please enter your email address.'));
        }
        else
        {
            if (!is_email($email))
            {
                $this->wp_error->add('email_invalid', __('Please enter a valid email address.'));
            }
        }

        // Validate password
        if (trim($pass) == '' || trim($conPass) == '')
        {
            $this->wp_error->add('pass_empty', __('Please enter a password.'));
        }
        else
        {
            if (strlen($pass) < 5)
            {
                $this->wp_error->add('pass_small', __('Password is too short.'));
            }
            if ($pass != $conPass)
            {
                $this->wp_error->add('pass_fields_unequal', __('Passwords do not match.'));
            }
        }
        $errors = $this->wp_error->get_error_messages();
        // Only create the user if there are no errors
        if (empty($errors))
        {
            $new_user_record = array(
                'user_login' => $username,
                'user_pass' => $pass,
                'user_registered' => date('Y-m-d H:i:s'),
                'role' => 'subscriber'
            );

            $new_user_id = wp_insert_user($new_user_record);
            if (!is_numeric($new_user_id))
            {
                var_dump($new_user_id);
                echo "<br />";
                die('Error in user registration. <a href="' . site_url() . '">Please contact us.</a>');
            }
            else
            {
                $new_user_id = wp_update_user(array('ID' => $new_user_id, 'user_email' => $email));
            }

            if (!is_numeric($new_user_id))
            {
                var_dump($new_user_id);
                echo "<br />";
                die('Error in user registration (2). <a href="' . site_url() . '">Please contact us.</a>');
            }

            if ($new_user_id)
            {
                $to = $email;
                $body = "Hello " . $username . "!";
                $body .= "\n\nWelcome to \"" . get_bloginfo('name') . "\". Thank you for registering.";
                $body .= "\n\nYour username is: " . $new_user_record['user_login'];
                $body .= "\nYour new password is: " . $new_user_record['user_pass'];
                $body .= "\nPlease log in using the provided username and password.";
                $body .= "\n" . site_url() . "/sign-in";
                $body .= "\n\nAfter logging in, change your password for security.";
                $body .= "\n\nDo not reply to this email.";
                $body .= "\n\n";

                wp_mail($to, "[" . get_bloginfo('name') . "] Thank you for registering, " . $username, $body);

                wp_set_current_user($new_user_id, $username);
                wp_set_auth_cookie($new_user_id);
                do_action('wp_login', $username);
                wp_redirect(site_url());
                exit;
            }
        }
    }
}


    private function is_valid_username($un)
    {
        $un_chars = array('.', '-', '_');
        $valid = true;
        $valid = $valid && ctype_alpha(substr($un, 0, 1));
        $valid = $valid && (strlen($un) >= 4);
        $valid = $valid && $this->is_valid_string($un, $un_chars);
        return $valid;
    }

    private function is_valid_string($s, $chars = array())
    {
        return ctype_alnum(str_replace($chars, '', $s));
    }

}
