for path in "" "jenkins" "jenkins/" "script" "asynchPeople" "manage"; do                  
  echo "Testing: /$path"                                                                  
  curl -s -o /dev/null -w "  Status: %{http_code}\n" "http://10.129.228.112:50000/$path"  
done    
