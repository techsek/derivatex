package commands

import (
	"fmt"
	"strconv"

	"github.com/fatih/color"
	"github.com/techsek/derivatex/constants"
)

func Help() {
	fmt.Println(color.HiWhiteString("derivatex usage:") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("create") + " " + color.HiCyanString("[-password=] [-birthdate=] [-user=] [-pin=]") + "\n" + color.HiWhiteString("Create the master password digest needed to generate passwords interactively (safer) and/or with command line flags (riskier due to commands history saved).") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("generate") + " " + color.HiGreenString("websitename") + " " + color.HiCyanString("[-length="+strconv.FormatInt(constants.DefaultPasswordLength, 10)+"] [-birthdate=] [-user=] [-pin=] [-qrcode=true] [-clipboard=true] [-passwordonly] [-save=true] [-version="+strconv.FormatInt(constants.Version, 10)+"]") + "\n" + color.HiWhiteString("Generate a password for a particular website name. Optional flags are available for custom password generation.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("list") + " " + color.HiCyanString("[-startdate=] [-enddate=] [-user=]") + "\n" + color.HiWhiteString("List all identifications. Optionally set a start date and end date (dd/mm/yyyy) and a specific user.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("search") + " " + color.HiGreenString("querystring") + " " + color.HiCyanString("[-websites=true] [-users=true]") + "\n" + color.HiWhiteString("Search identifications containing the query string. Optionally restrict the fields to search in.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("delete") + " " + color.HiGreenString("websitename") + " " + color.HiCyanString("[-user=]") + "\n" + color.HiWhiteString("Delete an identifications matching the website name. Optionally set the user in case there are multiple users registered for this website.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("dump") + " " + color.HiCyanString("[-tablename="+constants.DefaultTableToDump+"] [-outputfilename="+constants.DefaultTableToDump+".csv]") + "\n" + color.HiWhiteString("Dump a database table to a CSV file. Optionally set a different table to dump and/or a different output filename.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("help") + "\n" + color.HiWhiteString("Displays this usage message."))
}
