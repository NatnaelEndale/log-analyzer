
from src import Parser, Detection, Pipeline, Analyzer, Report
from pathlib import Path
import argparse

def main():
    current_dir = Path(__file__).parent
    json_file_path = current_dir/"output"/"log_analysis_report.json"
    parser = argparse.ArgumentParser(description= "A Log Analyzer")
    subparsers = parser.add_subparsers(dest= "command", help= "Available commands.")

    analyze_parser = subparsers.add_parser("analyze", help= "Perform a log analysis in the specified log file.")
    analyze_parser.add_argument("log_file", help= "A log file to Analyze.")
    analyze_parser.add_argument("--output", help= "Specified json file to store the output.", default= json_file_path)

    args = parser.parse_args()
    input_path = Path(args.output)
    # Continue from here
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")


    if args.command == "analyze":
        log_file_path = args.log_file
        pipe_object = Pipeline(log_file_path, args.output)
        pipe_object.store_to_json()



    
 #   parser_object = Parser()
#    result_list = parser_object.parsing(log_file_path)
#    analyzer_object = Analyzer(json_file_path)
    #report_object = Report(json_file_path)
    #report_object.report()
    #report_object.summary()
    #report_object.top_susp_ips()
    #report_object.top_endpoints()
  

if __name__ == "__main__":
    main()

