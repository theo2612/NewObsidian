for path in "script" "manage" "credentials" "configure" "log" "systemInfo"; do      
  echo "Testing: /askjeeves/$path"                                                  
  curl -s -o /dev/null -w "  Status: %{http_code}\n"                                
"http://10.129.228.112:50000/askjeeves/$path"                                       
done  
