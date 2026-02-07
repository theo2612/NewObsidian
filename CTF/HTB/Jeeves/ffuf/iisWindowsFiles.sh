for file in "web.config" "Web.config" "robots.txt" "sitemap.xml" "error.html"; do         
  echo "Testing: /$file"                                                                  
  curl -s -o /dev/null -w "  Status: %{http_code}\n" "http://10.129.228.112/$file"        
done 
