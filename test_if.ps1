$result = @{MaxAge=10}; $maxAge = if ($null -ne $result.MaxAge) { $result.MaxAge } else { "not found" }; echo $maxAge
