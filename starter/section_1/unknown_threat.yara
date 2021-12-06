rule unknown_threat{
	meta:
		author = "Manh Hung"
		date = "05 Dec 2021"
	strings:
		$url = "darkl0rd.com"
	condition:
		any of them
}