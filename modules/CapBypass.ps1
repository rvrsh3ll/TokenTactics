function Invoke-ForgeUserAgent
{
      <#
    .DESCRIPTION
        Forge the User-Agent when sending requests to the Microsoft API's. Useful for bypassing device specific Conditional Access Policies. Defaults to Windows Edge.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    Process
    {
        if ($Device -eq 'Mac')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
            }
        }
        elseif ($Device -eq 'Windows')
        {
            if ($Browser -eq 'IE')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            }
        }
        elseif ($Device -eq 'AndroidMobile')
        {
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM4.171019.021.D1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.109 Mobile Safari/537.36 EdgA/42.0.0.2057'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
        }
        elseif ($Device -eq 'iPhone')
        {
            if ($Browser -eq 'Chrome')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Firefox')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
            }
            elseif ($Browser -eq 'Edge')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
            }
            elseif ($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
            else 
            {
                $UserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
            }
        }
        else 
        {
            #[ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
            if ($Browser -eq 'Android')
            {
                $UserAgent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
            }
            elseif($Browser -eq 'IE')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
            }
            elseif($Browser -eq 'Chrome')
            { 
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
            }
            elseif($Browser -eq 'Firefox')
            { 
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
            }
            elseif($Browser -eq 'Safari')
            {
                $UserAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15' 
            }
            else
            {
                $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
            } 
        }
        return $UserAgent
   }   
}
