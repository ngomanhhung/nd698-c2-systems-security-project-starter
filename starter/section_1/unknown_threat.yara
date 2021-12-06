rule unknown_threat{
	meta:
		author = "Manh Hung"
		date = "05 Dec 2021"
	strings:
		$url = "darkl0rd.com:7758"
		$id1 = "SSH-T"
		$id2 = "SSH-One"
		$id3 = "darkl0rd"
	condition:
		any of them
}