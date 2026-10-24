
from src import Parser, Detection, Pipeline, Analyzer, Report
from pathlib import Path
import argparse

# Entry point of the program(CLI)
def main():
    current_dir = Path(__file__).parent
    json_file_path = current_dir/"output"/"log_analysis_report.json"
    parser = argparse.ArgumentParser(description= "A Log Analyzer")
    subparsers = parser.add_subparsers(dest= "command", help= "Available commands.")

    analyze_parser = subparsers.add_parser("analyze", help= "Perform a log analysis in the specified log file.")
    analyze_parser.add_argument("log_file", help= "A log file to Analyze.")
    analyze_parser.add_argument("--output", help= "Specified json file to store the output.", default= json_file_path)

    report_parser = subparsers.add_parser("report", help= "Generate a report from the analyzed log data.")
    report_parser.add_argument("--input", help= "Specified json file to generate the report from.", default= json_file_path)

    args = parser.parse_args()
    
    if args.output: # what is wrong in this line? I think it is not working as expected. I want to create the output directory if it does not exist.
        output_path = Path(args.output)
        if not output_path.parent.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)



    if args.log_file:
        input_path = Path(args.log_file)
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_path}")




    if args.command == "analyze":
        log_file_path = args.log_file
        output_path = Path(args.output)
        pipe_object = Pipeline(input_path, output_path)
        pipe_object.store_to_json()

    elif args.command == 'report':
        report_object = Report(json_file_path)
        report_object.report()
        report_object.summary()
        report_object.top_susp_ips()
        report_object.top_endpoints()


  

if __name__ == "__main__":
    main()

