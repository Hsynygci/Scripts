<!DOCTYPE html>
<html lang="en">
<head>
    <title>Example of PHP $_REQUEST variable</title>
</head>
<body>
<?php
if(!empty($_POST["name"]) && !empty($_POST["password"])){
    $stEntry="";
    $arLogData['event_datetime'] = '['.date('D Y-m-d h:i:s A').'] [from ==> '.$_SERVER['REMOTE_ADDR'].']';
    $logmsg = "login attemp!!";


    $stEntry.= $arLogData['event_datetime']. " ".$logmsg. "\r\n";
    
    //create file with current date name  
    $stCurLogFileName='log'.'.txt'; 
    //open the file append mode,dats the log file will create day wise  
    $fHandler=fopen($stCurLogFileName,'a+');  

    //write the info into the file  
    fwrite($fHandler,$stEntry);  
    //close handler  
    fclose($fHandler); 

    echo 'Login Failed.';
}
?>
<form method="post" action="<?php echo $_SERVER["PHP_SELF"];?>">
    <label for="inputName">Name:</label>
    <input type="text" name="name" id="inputName">
	<label for="inputName">Password:</label>
	<input type="password" name="password" id="password">
    <input type="submit" value="Login" name="Login">
</form>
</body>
