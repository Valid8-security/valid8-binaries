using System;

public class Calculator
{
    public static int CalculateSum(int a, int b)
    {
        return a + b;
    }

    public static void Main(string[] args)
    {
        int result = CalculateSum(5, 3);
        Console.WriteLine($"Result: {result}");
    }
}