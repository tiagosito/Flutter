//Page Lifecycle

class StatefulWidgetLifecycle extends StatefulWidget {
  @override
  _StatefulWidgetLifecycleState createState() => _StatefulWidgetLifecycleState();
}

class _StatefulWidgetLifecycleState extends State<StatefulWidgetLifecycle> with WidgetsBindingObserver {
 
  @override
  void initState() {
    super.initState();
    debugPrint('void initState()');
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _afterPageLoad(context));
  }

  _afterPageLoad(BuildContext context) async {
    //Hide Keyboard if is open
    var result = await getSomething();
    if(result.isNotEmpty){

    //.
    //.
    //.
    
    }
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    debugPrint('void didChangeDependencies()');
  }

  @override
  void didUpdateWidget(covariant StatefulWidgetLifecycle oldWidget) {
    super.didUpdateWidget(oldWidget);
    debugPrint('void didUpdateWidget()');
  }

  @override
  void dispose() {
    super.dispose();
    debugPrint('void dispose()');
    WidgetsBinding.instance.removeObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    debugPrint('void didChangeAppLifecycleState()');

    switch (state) {
      case AppLifecycleState.resumed:
        debugPrint('void didChangeAppLifecycleState() --> resumed');
        break;
      case AppLifecycleState.inactive:
        debugPrint('void didChangeAppLifecycleState() --> inactive');
        break;
      case AppLifecycleState.paused:
        debugPrint('void didChangeAppLifecycleState() --> paused');
        break;
      case AppLifecycleState.detached:
        debugPrint('void didChangeAppLifecycleState() --> detached');
        break;
    }
  }

  Future<String> getSomething()async{
    await Future.delayed(Duration(milliseconds: 350));
    return 'Ok';
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(),
    );
  }
}
