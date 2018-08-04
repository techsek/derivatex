package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

// TODO clipboard Linux, Unix (requires 'xclip' or 'xsel' command to be installed)

func main() {
	err := initiateDatabaseIfNeeded()
	if err != nil {
		color.HiRed("Error initiating database file '" + databaseFilename + "' (" + err.Error() + ")")
		return
	}
	if len(os.Args) == 1 {
		fmt.Println(color.HiWhiteString("Launching user interface..."))
	} else {
		cli(os.Args[1:])
	}
}

// func displayTime(seconds float64) string {
// 	formater := "%.1f %s"
// 	minute := float64(60)
// 	hour := minute * float64(60)
// 	day := hour * float64(24)
// 	month := day * float64(31)
// 	year := month * float64(12)
// 	century := year * float64(100)
// 	if seconds < minute {
// 		return "a few seconds"
// 	} else if seconds < hour {
// 		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/minute)), "minutes")
// 	} else if seconds < day {
// 		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/hour)), "hours")
// 	} else if seconds < month {
// 		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/day)), "days")
// 	} else if seconds < year {
// 		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/month)), "months")
// 	} else if seconds < century {
// 		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/century)), "years")
// 	} else {
// 		return "centuries"
// 	}
// }
