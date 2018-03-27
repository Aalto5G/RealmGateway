<!-- #Very very simple website for returning hostname of machine server is running on -->
<html>
 <head>
  <title>Hostname test</title>
 </head>
 <body>
 <?php 
$hostname = gethostname();
echo '<p>My hostname is: ' . $hostname . '</p>'; 
?>
<h2>Aalto</h2>
<img src="aalto.jpg" alt="Aalto logo" style="width:175px;height:113px;">

<h2>Some code</h2>
<img src="code1.jpeg" alt="Some code" style="width:720px;height:1080px;">

<h2>More code</h2>
<img src="code2.jpeg" alt="More code" style="width:720px;height:480px;">

<h2>Even more code</h2>
<img src="code3.png" alt="Even more code" style="width:720px;height:487px;">


<p><a href="images.html">More images</a></p>
 </body>
</html>
